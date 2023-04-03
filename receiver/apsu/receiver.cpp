// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <future>
#include <sstream>
#include <fstream>

// APSU
#include "apsu/crypto_context.h"
#include "apsu/log.h"
#include "apsu/network/channel.h"
#include "apsu/network/result_package.h"
#include "apsu/psu_params.h"
#include "apsu/seal_object.h"
#include "apsu/receiver.h"
#include "apsu/thread_pool_mgr.h"
#include "apsu/util/stopwatch.h"
#include "apsu/util/utils.h"

// SEAL
#include "seal/evaluator.h"
#include "seal/modulus.h"
#include "seal/util/common.h"

//Kunlun
#include "Kunlun/mpc/ot/naor_pinkas_ot.hpp"
#include "Kunlun/mpc/peqt/peqt_from_ddh.hpp"

//PAILLIER
#include "PaillierLibrarySamples/paillier.c"

using milliseconds_ratio = std::ratio<1, 1000>;
using duration_millis = std::chrono::duration<double, milliseconds_ratio>;
using namespace std;
using namespace seal;
using namespace seal::util;

namespace apsu {
    using namespace util;
    using namespace network;
    using namespace oprf;

    namespace receiver {

        namespace {
            std::vector<std::vector<block> > random_map_block;
            vector<block> random_matrix;
            vector<uint64_t> random_matrix2;
            template <typename T>
            bool has_n_zeros(T *ptr, size_t count)
            {
                return all_of(ptr, ptr + count, [](auto a) { return a == T(0); });
            }

            inline oc::block vec_to_oc_block(const std::vector<uint64_t> &in, size_t felts_per_item, uint64_t plain_modulus){
                uint32_t plain_modulus_len = 1;
                while(((1<<plain_modulus_len)-1)<plain_modulus){
                    plain_modulus_len++;
                }
                uint64_t plain_modulus_mask = (1<<plain_modulus_len)-1;
                uint64_t plain_modulus_mask_lower = (1<<(plain_modulus_len>>1))-1;
                uint64_t plain_modulus_mask_higher = plain_modulus_mask-plain_modulus_mask_lower;

                uint64_t lower=0,higher=0;
                if(felts_per_item&1){
                    lower = (in[felts_per_item-1] & plain_modulus_mask_lower);
                    higher = ((in[felts_per_item-1] & plain_modulus_mask_higher) >>((plain_modulus_len>>1)-1));
                }
                for(int pla = 0;pla < felts_per_item;pla+=2){
                    lower = ((in[pla] & plain_modulus_mask) | (lower<<plain_modulus_len));
                    higher = ((in[pla+1] & plain_modulus_mask) | (higher<<plain_modulus_len));
                }
                return oc::toBlock(higher,lower);
            }

            inline block vec_to_std_block(const std::vector<uint64_t> &in, size_t felts_per_item, uint64_t plain_modulus){
                uint32_t plain_modulus_len = 1;
                while(((1<<plain_modulus_len)-1)<plain_modulus){
                    plain_modulus_len++;
                }
                uint64_t plain_modulus_mask = (1<<plain_modulus_len)-1;
                uint64_t plain_modulus_mask_lower = (1<<(plain_modulus_len>>1))-1;
                uint64_t plain_modulus_mask_higher = plain_modulus_mask-plain_modulus_mask_lower;
                // cout<<"masks"<<endl;
                // cout<<hex<<plain_modulus<<endl;
                // cout<<hex<<plain_modulus_mask_lower<<endl;
                // cout<<hex<<plain_modulus_mask_higher<<endl;
                uint64_t lower=0,higher=0;
                if(felts_per_item&1){
                    lower = (in[felts_per_item-1] & plain_modulus_mask_lower);
                    higher = ((in[felts_per_item-1] & plain_modulus_mask_higher) >>((plain_modulus_len>>1)-1));
                }
                for(int pla = 0; pla < felts_per_item-1; pla+=2){
                    lower = ((in[pla] & plain_modulus_mask) | (lower<<plain_modulus_len));
                    higher = ((in[pla+1] & plain_modulus_mask) | (higher<<plain_modulus_len));
                }
                return Block::MakeBlock(higher,lower);
            }

            #define block_oc_to_std(a) (Block::MakeBlock((oc::block)a.as<uint64_t>()[1],(oc::block)a.as<uint64_t>()[0]))
        } // namespace

        oc::Timer all_timer;

        void Receiver::RunParams(
            const ParamsRequest &params_request,
            shared_ptr<ReceiverDB> receiver_db,
            network::Channel &chl,
            function<void(Channel &, Response)> send_fun)
        {
            STOPWATCH(recv_stopwatch, "Receiver::RunParams");
            all_timer.setTimePoint("RunParames start");
            if (!params_request) {
                APSU_LOG_ERROR("Failed to process parameter request: request is invalid");
                throw invalid_argument("request is invalid");
            }

            // Check that the database is set
            if (!receiver_db) {
                throw logic_error("ReceiverDB is not set");
            }

            APSU_LOG_INFO("Start processing parameter request");
         
   
            ParamsResponse response_params = make_unique<ParamsResponse::element_type>();
            response_params->params = make_unique<PSUParams>(receiver_db->get_params());
            
            try {
                send_fun(chl, move(response_params));
            } catch (const exception &ex) {
                APSU_LOG_ERROR(
                    "Failed to send response to parameter request; function threw an exception: "
                    << ex.what());
                throw;
            }

            APSU_LOG_INFO("Finished processing parameter request");
            all_timer.setTimePoint("RunParames finish");
        }

        void Receiver::RunOPRF(
            const OPRFRequest &oprf_request,
            OPRFKey key,
            network::Channel &chl,
            function<void(Channel &, Response)> send_fun)
        {
            STOPWATCH(recv_stopwatch, "Receiver::RunOPRF");

            if (!oprf_request) {
                APSU_LOG_ERROR("Failed to process OPRF request: request is invalid");
                throw invalid_argument("request is invalid");
            }

            APSU_LOG_INFO(
                "Start processing OPRF request for " << oprf_request->data.size() / oprf_query_size
                                                     << " items");

            // OPRF response has the same size as the OPRF query
            OPRFResponse response_oprf = make_unique<OPRFResponse::element_type>();
            try {
                response_oprf->data = OPRFSender::ProcessQueries(oprf_request->data, key);
            } catch (const exception &ex) {
                // Something was wrong with the OPRF request. This can mean malicious
                // data being sent to the receiver in an attempt to extract OPRF key.
                // Best not to respond anything.
                APSU_LOG_ERROR("Processing OPRF request threw an exception: " << ex.what());
                return;
            }

            try {
                send_fun(chl, move(response_oprf));
            } catch (const exception &ex) {
                APSU_LOG_ERROR(
                    "Failed to send response to OPRF request; function threw an exception: "
                    << ex.what());
                throw;
            }

            APSU_LOG_INFO("Finished processing OPRF request");
        }

        void Receiver::RunQuery(
            const Query &query,
            Channel &chl,
            function<void(Channel &, Response)> send_fun,
            function<void(Channel &, ResultPart)> send_rp_fun
           )
        {
            all_timer.setTimePoint("RunQuery start");
            // random_map.clear();
            random_after_permute_map.clear();
            random_plain_list.clear();
            
            
            if (!query) {
                APSU_LOG_ERROR("Failed to process query request: query is invalid");
                throw invalid_argument("query is invalid");
            }

            // We use a custom SEAL memory that is freed after the query is done
            auto pool = MemoryManager::GetPool(mm_force_new);

            ThreadPoolMgr tpm;

            // Acquire read lock on ReceiverDB
            auto receiver_db = query.receiver_db();
            auto receiver_db_lock = receiver_db->get_reader_lock();

            STOPWATCH(recv_stopwatch, "Receiver::RunQuery");
            APSU_LOG_INFO(
                "Start processing query request on database with " << receiver_db->get_item_count()
                                                                   << " items");

            // Copy over the CryptoContext from ReceiverDB; set the Evaluator for this local instance.
            // Relinearization keys may not have been included in the query. In that case
            // query.relin_keys() simply holds an empty seal::RelinKeys instance. There is no
            // problem with the below call to CryptoContext::set_evaluator.
            CryptoContext crypto_context(receiver_db->get_crypto_context());
            crypto_context.set_evaluator(query.relin_keys());

            // Get the PSUParams
            PSUParams params(receiver_db->get_params());

            uint32_t bundle_idx_count = safe_cast<uint32_t>(params.bundle_idx_count());
            uint32_t max_items_per_bin = safe_cast<uint32_t>(params.table_params().max_items_per_bin);

            // Extract the PowersDag
            PowersDag pd = query.pd();

            // get the col of the matrix 
            size_t max_bin_bundle_conut_alpha = 0;
            std::vector<size_t> cache_cnt_per_bundle;
            for (size_t bundle_idx = 0; bundle_idx < bundle_idx_count; bundle_idx++) {
                cache_cnt_per_bundle.emplace_back(receiver_db->get_bin_bundle_count(static_cast<uint32_t>(bundle_idx)));
                max_bin_bundle_conut_alpha = std::max(max_bin_bundle_conut_alpha,
                    cache_cnt_per_bundle[bundle_idx]);
            }

            // The query response only tells how many ResultPackages to expect; send this first
            uint32_t package_count = safe_cast<uint32_t>(receiver_db->get_bin_bundle_count());
            QueryResponse response_query = make_unique<QueryResponse::element_type>();
            response_query->package_count = package_count;
            response_query->alpha_max_cache_count = max_bin_bundle_conut_alpha;

            item_cnt = bundle_idx_count * safe_cast<uint32_t>(params.items_per_bundle());

            try {
                send_fun(chl, move(response_query));
            } catch (const exception &ex) {
                APSU_LOG_ERROR(
                    "Failed to send response to query request; function threw an exception: "
                    << ex.what());
                throw;
            }
            
            random_map_block.reserve(bundle_idx_count);
            
            // generate random number
            {
                all_timer.setTimePoint("random gen start");
                // prepare PRNG
                vector<uint64_t> random_num;
                vector<uint64_t> random_num2;
                prng_seed_type newseed;
                random_bytes(reinterpret_cast<seal_byte *>(newseed.data()), prng_seed_byte_count);
                UniformRandomGeneratorInfo myGEN(prng_type::blake2xb, newseed);
                std::shared_ptr<UniformRandomGenerator> myprng = myGEN.make_prng();
                auto context_data = crypto_context.seal_context()->last_context_data();
                // cout << "mod q" << endl;
                // random mod q
                //cout << context_data->parms().coeff_modulus().back().value() << endl;
                plain_modulus = context_data->parms().plain_modulus().value();
                auto encoder = crypto_context.encoder();
                size_t slot_count = encoder->slot_count();

                size_t felts_per_item = safe_cast<size_t>(params.item_params().felts_per_item);
                size_t items_per_bundle = safe_cast<size_t>(params.items_per_bundle());                
               
                for(size_t cache_idx = 0;cache_idx < max_bin_bundle_conut_alpha;cache_idx++)
                 {
                    for (size_t bundle_idx = 0; bundle_idx < bundle_idx_count; bundle_idx++){
                        // judge need to padding the cache
                        bool padding_to_max_cache_size=(cache_idx>=cache_cnt_per_bundle[bundle_idx]);
                //        APSU_LOG_INFO("error"<<cache_idx<<' '<<cache_cnt_per_bundle[bundle_idx]);
                        if(padding_to_max_cache_size){  
                            
                            for(size_t i = 0;i< items_per_bundle;i++){
                                random_matrix.emplace_back(Block::all_one_block);
                                random_matrix2.emplace_back(0);
                            }
                            continue;
                        }
                        
                        Plaintext random_plain(pool);
                        Plaintext random_plain2(pool);
                        random_num.clear();
                        random_num2.clear();

                        for (int i = 0; i < slot_count; i++)
                        {
                            random_num.emplace_back(myprng->generate() % plain_modulus);                                              
                            random_num2.emplace_back(myprng->generate() % plain_modulus);
                            
                            //random_num.emplace_back(0);
                            //random_num.push_back(i % small_q);
                            //random_num.push_backrandom_matrix2(0);
                        }
                        
                        for(size_t i = 0; i < items_per_bundle; i++){
                            vector<uint64_t> rest(felts_per_item,0);
                            vector<uint64_t> rest2(felts_per_item,0);
                            for(size_t j = 0; j < felts_per_item; j++){
                                rest[j] = random_num[i*felts_per_item+j];
                                rest2[j] = random_num2[i*felts_per_item+j];
                            }
                            //random_map_block[bundle_idx].emplace_back(vec_to_std_block(move(rest),felts_per_item,plain_modulus));
                            random_matrix.emplace_back(vec_to_std_block(move(rest), felts_per_item, plain_modulus));
                            random_matrix2.emplace_back(plain_modulus - rest2[0]);
                        }

                      //  APSU_LOG_INFO("cbp_idx"<<cache_idx<<' '<<bundle_idx<<' '<<random_plain_list.size());

                        encoder->encode(random_num, random_plain);
                        encoder->encode(random_num2, random_plain2);
                        random_plain_list.emplace_back(random_plain);
                        random_plain_list2.emplace_back(random_plain2);
                        // random_map.emplace_back(random_num);
                        // random_map2.emplace_back(random_num2);
                      
                        // for(auto x :  random_map[0])
                        //     std::cout<<x<<endl;
                    }
                                  
                }
                all_timer.setTimePoint("random gen finish");
                APSU_LOG_INFO("plain_mod = " << plain_modulus);                
            }

            // For each bundle index i, we need a vector of powers of the query Qᵢ. We need powers
            // all the way up to Qᵢ^max_items_per_bin. We don't store the zeroth power. If
            // Paterson-Stockmeyer is used, then only a subset of the powers will be populated.
            vector<CiphertextPowers> all_powers(bundle_idx_count);
            all_timer.setTimePoint("compute power start");

            // Initialize powers
            for (CiphertextPowers &powers : all_powers) {
                // The + 1 is because we index by power. The 0th power is a dummy value. I promise
                // this makes things easier to read.
                size_t powers_size = static_cast<size_t>(max_items_per_bin) + 1;
                powers.reserve(powers_size);
                for (size_t i = 0; i < powers_size; i++) {
                    powers.emplace_back(pool);
                }
            }

            // Load inputs provided in the query
            for (auto &q : query.data()) {
                // The exponent of all the query powers we're about to iterate through
                size_t exponent = static_cast<size_t>(q.first);

                // Load Qᵢᵉ for all bundle indices i, where e is the exponent specified above
                for (size_t bundle_idx = 0; bundle_idx < all_powers.size(); bundle_idx++) {
                    // Load input^power to all_powers[bundle_idx][exponent]
                    APSU_LOG_DEBUG(
                        "Extracting query ciphertext power " << exponent << " for bundle index "
                                                             << bundle_idx);
                    all_powers[bundle_idx][exponent] = move(q.second[bundle_idx]);
                }
            }

            // Compute query powers for the bundle indexes
            for (size_t bundle_idx = 0; bundle_idx < bundle_idx_count; bundle_idx++) {
                ComputePowers(
                    receiver_db,
                    crypto_context,
                    all_powers,
                    pd,
                    static_cast<uint32_t>(bundle_idx),
                    pool);
            }
            all_timer.setTimePoint("compute power finished");

            APSU_LOG_DEBUG("Finished computing powers for all bundle indices");
            APSU_LOG_DEBUG("Start processing bin bundle caches");
            pack_cnt=0;
            vector<future<void>> futures;
            for (size_t bundle_idx = 0; bundle_idx < bundle_idx_count; bundle_idx++) {
                auto bundle_caches = receiver_db->get_cache_at(static_cast<uint32_t>(bundle_idx));
                size_t cache_idx = 0;
               // APSU_LOG_INFO(cache_idx);
                for (auto &cache : bundle_caches) {
                    pack_cnt++;
                    size_t pack_idx = bundle_idx+cache_idx*bundle_idx_count;
                    //cout << "pack_idx = " << pack_idx << " bundle_idx = " << bundle_idx << " cache_idx = " << cache_idx << " bundle_idx_count = " << bundle_idx_count << endl;
                    futures.push_back(tpm.thread_pool().enqueue([&, bundle_idx, cache,cache_idx,pack_idx]() {
                        ProcessBinBundleCache(
                            receiver_db,
                            crypto_context,
                            cache,
                            all_powers,
                            chl,
                            send_rp_fun,
                            static_cast<uint32_t>(bundle_idx),
                            query.compr_mode(),
                            pool,
                            cache_idx,
                            pack_idx
                            );
                    }));
                    cache_idx++;
                }
            }

            // Wait until all bin bundle caches have been processed
            for (auto &f : futures) {
                f.get();
            }
            
#if ARBITARY == 0 
            
            std::vector<uint8_t> vec_result;
            NetIO server("server","",59999);
            {
                Global_Initialize(); 
                ECGroup_Initialize(NID_X9_62_prime256v1); 
                
                APSU_LOG_INFO("random_matrix size = " << random_matrix.size() << " item_cnt = "<< item_cnt << " alpha_max_cache_count = " <<max_bin_bundle_conut_alpha);
                vec_result = DDHPEQT::Receive(server, random_matrix, max_bin_bundle_conut_alpha, item_cnt);

                ECGroup_Finalize(); 
                Global_Finalize();  
            }

            for(size_t cache_idx = 0; cache_idx < max_bin_bundle_conut_alpha; cache_idx++){
                for(size_t item_idx = 0; item_idx < item_cnt; item_idx++){
                    if(vec_result[cache_idx*item_cnt + item_idx]) 
                    {
                        //std::cout << "cache_idx*item_cnt + item_idx = " << cache_idx*item_cnt + item_idx << std::endl;
                        ans.emplace_back(item_idx);
                    }  
                }
            }
     
            all_timer.setTimePoint("ProcessBinBundleCache finished");
            APSU_LOG_INFO("Finished processing query request");

            // card and sum
            RunOT(); 

    #if SSINTERSECTION == 1
        osuCrypto::BitVector choices(item_cnt);
        APSU_LOG_INFO(ans.size());
        server.SendInteger(ans.size());

        for(auto i : ans){
            choices[i] = 1;
        }

        std::vector<oc::block> S1;
        oc::block s;
        oc::block s_neg;
        osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

        char* hexPubKey = new char[257];
        server.ReceiveBytes(hexPubKey, 257);
        paillier_pubkey_t* pubKey = paillier_pubkey_from_hex(hexPubKey);
        //gmp_printf("pubKey: %Zd\n", pubKey->n);

        paillier_plaintext_t* ptxt;
        paillier_ciphertext_t* ctxt1;
        paillier_ciphertext_t* ctxt2;
        paillier_ciphertext_t* encrypted_sum = paillier_create_enc_zero();
        std::vector<char *> cipher_messages_char(choices.size());
        std::vector<char *> result_vec;
        char * s_neg_char = new char[16];
        //char * cipher_messages_char = new char[64];
        char * cipher_result_char;

        //std::cout << "choice size = " << choices.size() << std::endl;
        for(int i=0; i < choices.size(); i++){
            cipher_messages_char[i] = new char[256];
            server.ReceiveBytes(cipher_messages_char[i], 256);
        }

        for(int i=0; i < choices.size(); i++){
            if (choices[i])
            {
                s_neg = prng.get<oc::block>();
                //s_neg = oc::ZeroBlock - s;
                memcpy(s_neg_char, &s_neg, 16);
                //PrintBytes((uint8_t *)s_neg_char, 16);
                ptxt = paillier_plaintext_from_bytes(s_neg_char, 16);
                //gmp_printf("s_neg_char Plaintext: %Zd\n", ptxt);
                ctxt1 = paillier_enc(NULL, pubKey, ptxt, paillier_get_rand_devurandom);// ciphertext of s_neg
                ctxt2 = paillier_ciphertext_from_bytes(cipher_messages_char[i], 256);
                paillier_mul(pubKey, encrypted_sum, ctxt1, ctxt2);// ciphertext of s_neg + x_i
                cipher_result_char = (char*)paillier_ciphertext_to_bytes(256, encrypted_sum);
                result_vec.emplace_back(cipher_result_char);
                S1.emplace_back(s_neg);
            }    
        }

        //std::cout << "S1 size = " << S1.size() << std::endl;
        for (size_t i = 0; i < S1.size(); i++)
        {
            server.SendBytes(result_vec[i], 256);
        }

        //write S1 to file
        std::ofstream fout; 
        fout.open("share1.csv", std::ios::out); 

        for(auto i = 0; i < S1.size(); i++){
            uint64_t* data = (uint64_t*)&S1[i];
            std::stringstream ss;
            ss << std::hex << std::setw(16) << std::setfill('0') << data[1] << data[0] << std::endl;
            fout << std::flush << ss.str();   
        }

        fout.close();

        paillier_freepubkey(pubKey);
        paillier_freeplaintext(ptxt);
        paillier_freeciphertext(ctxt1);
        paillier_freeciphertext(ctxt2);
        paillier_freeciphertext(encrypted_sum);
        delete[] hexPubKey;
        delete[] s_neg_char;
        delete[] cipher_result_char;

        // paillier test
        // char* hexPubKey = new char[257];
        // server.ReceiveBytes(hexPubKey, 257);
        // PrintBytes((uint8_t*)hexPubKey, 257);
        // paillier_pubkey_t* pubKey = paillier_pubkey_from_hex(hexPubKey);
        // gmp_printf("pubKey: %Zd\n", pubKey->n);

        // char* s1 = new char[16];
        // server.ReceiveBytes(s1, 16);
        // PrintBytes((uint8_t*)s1, 16);
        // paillier_plaintext_t* ptxt1 = paillier_plaintext_from_bytes(s1, 16);
        // gmp_printf("Plaintext: %Zd\n", ptxt1);
        // paillier_ciphertext_t* ctxt3 = paillier_enc(NULL, pubKey, ptxt1, paillier_get_rand_devurandom);
        // char* ctxt_char1 = (char*)paillier_ciphertext_to_bytes(256, ctxt3);
        // PrintBytes((uint8_t*)ctxt_char1, 256);
        // server.SendBytes(ctxt_char1, 256);
        
    #endif            

#endif

#if CARDSUMWITHLABLE == 1
        // auto start_time = std::chrono::system_clock::now();
        const long n = 1024; 

        oc::IOService ios;
        oc::Session  ep0(ios, "localhost:60001", oc::SessionMode::Server);
        auto chls = ep0.addChannel();

        paillier_pubkey_t* pubKey;
        paillier_prvkey_t* secKey;
        paillier_keygen(n, &pubKey, &secKey, paillier_get_rand_devurandom);
        // gmp_printf("pubKey: %Zd\n", pubKey->n);

        char* hexPubKey = paillier_pubkey_to_hex(pubKey);
        chls.send(hexPubKey, 257);

        // send secKey for test
        // char* hexSecKey = paillier_prvkey_to_hex(secKey);
        // gmp_printf("secKey: %Zd\n", secKey->lambda);
        // server.SendBytes(hexSecKey, 257);

        char* ctxt_char = new char[256];
        paillier_plaintext_t* ptxt;
        paillier_ciphertext_t* ctxt;
        uint64_t matrix_size = random_matrix2.size();

        for (size_t i = 0; i < matrix_size; i++)
        {            
            ptxt = paillier_plaintext_from_ui(random_matrix2[i]);
            ctxt = paillier_enc(NULL, pubKey, ptxt, paillier_get_rand_devurandom);
            ctxt_char = (char*)paillier_ciphertext_to_bytes(256, ctxt);

            chls.send(ctxt_char, 256);
        }

        // auto end_time = std::chrono::system_clock::now();
        // duration_millis duration = end_time - start_time;
        // cout << "AHE encryption r time = "<< duration.count() << endl;

        // start_time = std::chrono::system_clock::now();

        osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
        std::vector<osuCrypto::block> PRGKeys(matrix_size);
        std::vector<osuCrypto::IknpOtExtReceiver> receiver(1);

        uint64_t cardinality = 0;
        osuCrypto::BitVector choices(matrix_size);
        for (auto i = 0; i < matrix_size; i++)
        {
            if (vec_result[i])
            {   
                cardinality ++;
                choices[i] = 1;
            }
        }
        
        receiver[0].receive(choices, PRGKeys, prng, chls);

        char* masked_str = new char[256];
        std::vector<char*> ctxt_m0(matrix_size); 
        std::vector<char*> ctxt_m1(matrix_size);

        for (auto i = 0; i < matrix_size; i++)
        {
            ctxt_m0[i] = new char[256];
            ctxt_m1[i] = new char[256];
        }

        for (auto i = 0; i < matrix_size; i++)
        {
            chls.recv(ctxt_m0[i], 256);
            chls.recv(ctxt_m1[i], 256);
        }

        // end_time = std::chrono::system_clock::now();
        // duration = end_time - start_time;
        // cout << "receive m0 and m1 time = "<< duration.count() << endl;

        // start_time = std::chrono::system_clock::now();

        // paillier_plaintext_t* dec;
        paillier_ciphertext_t* m_choose;
        // paillier_plaintext_t* dec_m_choose;
        paillier_ciphertext_t* encrypted_sum = paillier_create_enc_zero();
        paillier_plaintext_t* decrypted_sum;
        mpz_t result_sum;
        mpz_init(result_sum);
        mpz_set_ui(result_sum, 0);
        for (auto i = 0; i < matrix_size; i++)
        {
            prng.SetSeed(PRGKeys[i]);
            prng.get(masked_str, 256);

            if (choices[i] == 0)
            {
                xor_buffers((unsigned char *)ctxt_m0[i], (unsigned char *)masked_str, 256);
                m_choose = paillier_ciphertext_from_bytes(ctxt_m0[i], 256);
            }
            else
            { 
                //std::cout << i << " ";
                xor_buffers((unsigned char *)ctxt_m1[i], (unsigned char *)masked_str, 256);
                m_choose = paillier_ciphertext_from_bytes(ctxt_m1[i], 256);
                // dec = paillier_dec(NULL, pubKey, secKey, m_choose);

                // mpz_t label;
                // mpz_init(label);
                // mpz_mod_ui(label, dec->m, plain_modulus);
                // gmp_printf("%Zd\n", label);
            }
            paillier_mul(pubKey, encrypted_sum, encrypted_sum, m_choose);
            // dec_m_choose = paillier_dec(NULL, pubKey, secKey, m_choose);
            // mpz_mod_ui(dec_m_choose->m, dec_m_choose->m, plain_modulus);
            // mpz_add(result_sum, result_sum, dec_m_choose->m);
        } 
        decrypted_sum = paillier_dec(NULL, pubKey, secKey, encrypted_sum);

        // end_time = std::chrono::system_clock::now();
        // duration = end_time - start_time;
        // cout << "xor and mul time = "<< duration.count() << endl;

        std::cout << "\nresult cardinality = " << cardinality << std::endl;
        
        mpz_mod_ui(result_sum, decrypted_sum->m, plain_modulus);
        // mpz_mod_ui(result_sum, result_sum, plain_modulus*cardinality);
        gmp_printf("result sum = %Zd\n", result_sum);

        chls.close();
        ep0.stop();
        ios.stop();

        paillier_freepubkey(pubKey);
        paillier_freeprvkey(secKey);
        paillier_freeplaintext(ptxt);
        paillier_freeplaintext(decrypted_sum);    
        paillier_freeciphertext(ctxt);
        paillier_freeciphertext(m_choose);
        paillier_freeciphertext(encrypted_sum);
        delete[] masked_str;
        mpz_clear(result_sum);
        for (auto i = 0; i < matrix_size; i++)
        {
            delete[] ctxt_m0[i];
            delete[] ctxt_m1[i];
        }

#endif
  
        APSU_LOG_INFO(all_timer);
        }

        void Receiver::ComputePowers(
            const shared_ptr<ReceiverDB> &receiver_db,
            const CryptoContext &crypto_context,
            vector<CiphertextPowers> &all_powers,
            const PowersDag &pd,
            uint32_t bundle_idx,
            MemoryPoolHandle &pool)
        {
            STOPWATCH(recv_stopwatch, "Receiver::ComputePowers");
            auto bundle_caches = receiver_db->get_cache_at(bundle_idx);
            if (!bundle_caches.size()) {
                return;
            }

            // Compute all powers of the query
            APSU_LOG_DEBUG("Computing all query ciphertext powers for bundle index " << bundle_idx);

            auto evaluator = crypto_context.evaluator();
            auto relin_keys = crypto_context.relin_keys();

            CiphertextPowers &powers_at_this_bundle_idx = all_powers[bundle_idx];
            bool relinearize = crypto_context.seal_context()->using_keyswitching();
            pd.parallel_apply([&](const PowersDag::PowersNode &node) {
                if (!node.is_source()) {
                    auto parents = node.parents;
                    Ciphertext prod(pool);
                    if (parents.first == parents.second) {
                        evaluator->square(powers_at_this_bundle_idx[parents.first], prod, pool);
                    } else {
                        evaluator->multiply(
                            powers_at_this_bundle_idx[parents.first],
                            powers_at_this_bundle_idx[parents.second],
                            prod,
                            pool);
                    }
                    if (relinearize) {
                        evaluator->relinearize_inplace(prod, *relin_keys, pool);
                    }
                    powers_at_this_bundle_idx[node.power] = move(prod);
                }
            });

            // Now that all powers of the ciphertext have been computed, we need to transform them
            // to NTT form. This will substantially improve the polynomial evaluation,
            // because the plaintext polynomials are already in NTT transformed form, and the
            // ciphertexts are used repeatedly for each bin bundle at this index. This computation
            // is separate from the graph processing above, because the multiplications must all be
            // done before transforming to NTT form. We omit the first ciphertext in the vector,
            // because it corresponds to the zeroth power of the query and is included only for
            // convenience of the indexing; the ciphertext is actually not set or valid for use.

            ThreadPoolMgr tpm;

            // After computing all powers we will modulus switch down to parameters that one more
            // level for low powers than for high powers; same choice must be used when encoding/NTT
            // transforming the ReceiverDB data.
            auto high_powers_parms_id =
                get_parms_id_for_chain_idx(*crypto_context.seal_context(), 1);
            auto low_powers_parms_id =
                get_parms_id_for_chain_idx(*crypto_context.seal_context(), 2);

            uint32_t ps_low_degree = receiver_db->get_params().query_params().ps_low_degree;

            vector<future<void>> futures;
            for (uint32_t power : pd.target_powers()) {
                futures.push_back(tpm.thread_pool().enqueue([&, power]() {
                    if (!ps_low_degree) {
                        // Only one ciphertext-plaintext multiplication is needed after this
                        evaluator->mod_switch_to_inplace(
                            powers_at_this_bundle_idx[power], high_powers_parms_id, pool);

                        // All powers must be in NTT form
                        evaluator->transform_to_ntt_inplace(powers_at_this_bundle_idx[power]);
                    } else {
                        if (power <= ps_low_degree) {
                            // Low powers must be at a higher level than high powers
                            evaluator->mod_switch_to_inplace(
                                powers_at_this_bundle_idx[power], low_powers_parms_id, pool);

                            // Low powers must be in NTT form
                            evaluator->transform_to_ntt_inplace(powers_at_this_bundle_idx[power]);
                        } else {
                            // High powers are only modulus switched
                            evaluator->mod_switch_to_inplace(
                                powers_at_this_bundle_idx[power], high_powers_parms_id, pool);
                        }
                    }
                }));
            }

            for (auto &f : futures) {
                f.get();
            }
        }

        void Receiver::ProcessBinBundleCache(
            const shared_ptr<ReceiverDB> &receiver_db,
            const CryptoContext &crypto_context,
            reference_wrapper<const BinBundleCache> cache,
            vector<CiphertextPowers> &all_powers,
            Channel &chl,
            function<void(Channel &, ResultPart)> send_rp_fun,
            uint32_t bundle_idx,
            compr_mode_type compr_mode,
            MemoryPoolHandle &pool,
            uint32_t cache_idx,
            uint32_t pack_idx
            )
        {
            STOPWATCH(recv_stopwatch, "Receiver::ProcessBinBundleCache");
           // APSU_LOG_INFO("cbp_idx"<<cache_idx<<' '<<bundle_idx<<' '<<pack_idx<<"?");
            // Package for the result data
            auto rp = make_unique<ResultPackage>();
            rp->compr_mode = compr_mode;
            rp->cache_idx = cache_idx;
            rp->bundle_idx = bundle_idx;
            rp->nonce_byte_count = safe_cast<uint32_t>(receiver_db->get_nonce_byte_count());
            rp->label_byte_count = safe_cast<uint32_t>(receiver_db->get_label_byte_count());
            
            //APSU_LOG_INFO(random_plain_list.size());
            
            // Compute the matching result and move to rp
            const BatchedPlaintextPolyn &matching_polyn = cache.get().batched_matching_polyn;
            //random_plain.set_zero();
            // Determine if we use Paterson-Stockmeyer or not
            uint32_t ps_low_degree = receiver_db->get_params().query_params().ps_low_degree;
            uint32_t degree = safe_cast<uint32_t>(matching_polyn.batched_coeffs.size()) - 1;
            bool using_ps = (ps_low_degree > 1) && (ps_low_degree < degree);
            if (using_ps) {
                rp->psu_result = matching_polyn.eval_patstock(
                    crypto_context, all_powers[bundle_idx], safe_cast<size_t>(ps_low_degree), pool, random_plain_list[pack_idx]);
            } else {
                rp->psu_result = matching_polyn.eval(all_powers[bundle_idx], pool, random_plain_list[pack_idx]);
            }
            // random_plain.set_zero();

            // handle label
            for (const auto &interp_polyn : cache.get().batched_interp_polyns) {
                // Compute the label result and move to rp
                degree = safe_cast<uint32_t>(interp_polyn.batched_coeffs.size()) - 1;
                using_ps = (ps_low_degree > 1) && (ps_low_degree < degree);
                if (using_ps) {
                    rp->label_result.push_back(interp_polyn.eval_patstock(
                        crypto_context, all_powers[bundle_idx], ps_low_degree, pool, random_plain_list2[pack_idx]));
                } else {
                    rp->label_result.push_back(interp_polyn.eval(all_powers[bundle_idx], pool, random_plain_list2[pack_idx]));
                }
            }

            // Send this result part
            try {
                send_rp_fun(chl, move(rp));
            } catch (const exception &ex) {
                APSU_LOG_ERROR(
                    "Failed to send result part; function threw an exception: " << ex.what());
                throw;
            }
        }

        void Receiver::RunResponse(
            const plainRequest &plain_request, network::Channel &chl,const PSUParams &params_)
        {
      
      /*      for (auto i : params_request->psu_result) {
                cout << i << endl;
            }*/

            // To be atomic counter
        

            all_timer.setTimePoint("RunResponse start");

            size_t felts_per_item = safe_cast<size_t>(params_.item_params().felts_per_item);
            size_t items_per_bundle = safe_cast<size_t>(params_.items_per_bundle());
            size_t bundle_start =
                mul_safe(safe_cast<size_t>(plain_request->bundle_idx), items_per_bundle);
            ;
            ans.clear();
            item_cnt = plain_request->psu_result.size();

            for (int i = 0; i < item_cnt; i++) {
           /*     if (plain_request->psu_result[i] == random_mem[i]) {
                    cout << "success" << endl;

                }*/
                plain_request->psu_result[i] ^= random_after_permute_map[i];   
               // cout << (bool)plain_request->psu_result[i];
            }
           item_cnt /= felts_per_item;
            StrideIter<const uint64_t *> plain_rp_iter(
                plain_request->psu_result.data(), felts_per_item);
               seal_for_each_n(iter(plain_rp_iter, size_t(0)), item_cnt, [&](auto &&I) {
                // Find felts_per_item consecutive zeros
               bool match = has_n_zeros(get<0>(I).ptr(), felts_per_item);
                if (!match) {
                    return;
                }

                // Compute the cuckoo table index for this item. Then find the corresponding index
                // in the input items vector so we know where to place the result.
                size_t table_idx = add_safe(get<1>(I), bundle_start);
             
                ans.push_back(table_idx);
            });
            all_timer.setTimePoint("RunResponse finish");
            cout<<all_timer<<endl;

            //RunOT();

        }

        void Receiver::RunOT(){
            all_timer.setTimePoint("RunOT start");

            osuCrypto::BitVector choices(item_cnt);
            
            for(auto i : ans){
                choices[i] = 1;
            }

            std::cout << "\ncardinality = " << ans.size() << std::endl;
            //  for (auto i = 1; i < numThreads; ++i){
            //     receivers[i] = receivers[0].splitBase();
            // }
    #if CARDSUMWITHOUTLABLE == 1        
            int numThreads = 1;
            osuCrypto::IOService ios;
            oc::Session send_session=oc::Session(ios,"localhost:50000",oc::SessionMode::Server);
            std::vector<oc::Channel> send_chls(numThreads);
            
            osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
            
            for (int i = 0; i < numThreads; ++i)
                send_chls[i]=send_session.addChannel();
            std::vector<osuCrypto::IknpOtExtReceiver> receivers(numThreads);
            
            // osuCrypto::DefaultBaseOT base;
            // std::array<std::array<osuCrypto::block, 2>, 128> baseMsg;
            // base.send(baseMsg, prng, chls[0], numThreads);
            // receivers[0].setBaseOts(baseMsg, prng, chls[0]);

            std::vector<osuCrypto::block> messages(item_cnt);
            
            receivers[0].receiveChosen(choices, messages, prng, send_chls[0]);

            oc::block Sum = oc::ZeroBlock;
            std::uint64_t sum_bound = 1 << 32;
            for(auto i:messages){
                Sum = Sum + i;
                //std::cout << "elements = " << i << std::endl;
            }
            std::cout << "Sum = " << _mm_cvtsi128_si64(Sum) << std::endl;
            // std::ofstream fout;
            // fout.open("union.csv",std::ofstream::out);
            
            // for(auto i:messages){

            //     if(i == oc::ZeroBlock) continue;
            //     stringstream ss;
                
            //     ss<<i.as<uint8_t>().data();
            //     fout<<flush<<ss.str().substr(0,16)<<endl;
            // }
            // fout.close();

            APSU_LOG_INFO("OT send_com_size ps"<<send_chls[0].getTotalDataSent()/1024<<"KB");
            APSU_LOG_INFO("OT recv_com_size ps"<<send_chls[0].getTotalDataRecv()/1024<<"KB");
            all_timer.reset();
            send_chls[0].close();
            send_session.stop();
            ios.stop();
    #endif

            all_timer.setTimePoint("RunOT finish");
            //cout<<all_timer<<endl;
        }


//    void Receiver::RunOT(){
//             all_timer.setTimePoint("RunOT start");

//             int numThreads = 1;
//             osuCrypto::IOService ios;
//             oc::Session send_session=oc::Session(ios,"localhost:59999",oc::SessionMode::Server);
//             std::vector<oc::Channel> send_chls(numThreads);
            
//             osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
            
//             for (int i = 0; i < numThreads; ++i)
//                 send_chls[i]=send_session.addChannel();
//             std::vector<osuCrypto::IknpOtExtReceiver> receivers(numThreads);
//             cout<<hex<<item_cnt<<endl;
//             osuCrypto::BitVector choices(item_cnt);
//             APSU_LOG_INFO(ans.size());
//             for(auto i : ans){
//                 choices[i] = 1;
//             }

//             APSU_LOG_DEBUG("item_len"<<item_len);
            
//             std::vector<std::vector<osuCrypto::block > > messages;
//             messages.resize(item_len);

//             for(size_t item_turnc_idx = 0;item_turnc_idx<item_len;item_turnc_idx++){
//                 messages[item_turnc_idx].resize(item_cnt);
//                 APSU_LOG_INFO( messages[item_turnc_idx].size());
//                 receivers[0].receiveChosen(choices, messages[item_turnc_idx], prng, send_chls[0]);
//             }
            
//             std::ofstream fout;
//             fout.open("union.csv",std::ofstream::out);
//             for(size_t item_idx = 0;item_idx<item_cnt;item_idx++){
                
//                 if(messages[0][item_idx] == oc::ZeroBlock)
//                     continue;;
//                 for(size_t item_turnc_idx = 0;item_turnc_idx<item_len;item_turnc_idx++){
//                     auto temp = messages[item_turnc_idx][item_idx];
//                     if( temp == oc::ZeroBlock){                        
//                         break;
//                     }
//                     stringstream ss;
//                     ss<<temp.as<uint8_t>().data();
//                     fout<<flush<<ss.str().substr(0,16);                   
//                 }
               
//                 fout << endl;
//             }
//             all_timer.setTimePoint("RunOT finish");
//             cout<<all_timer<<endl;

//             APSU_LOG_INFO("OT send_com_size ps"<<send_chls[0].getTotalDataSent()/1024<<"KB");
//             APSU_LOG_INFO("OT recv_com_size ps"<<send_chls[0].getTotalDataRecv()/1024<<"KB");
//             all_timer.reset();
//             send_chls.clear();
//             send_session.stop();
//         }


#if  CARDSUM == 1
        void Receiver::Cardsum_receiver(){
            all_timer.setTimePoint("Cardsum_begin");
            Global_Initialize(); 
            ECGroup_Initialize(NID_X9_62_prime256v1); 
		    NetIO client("client", "127.0.0.1", 58888);
            size_t Card = ans.size();
            std::vector<uint8_t> vec_select_bit(item_cnt);
            for(auto x : ans){
                vec_select_bit[x] = 1;
            }
            auto pp = NPOT::Setup();
            APSU_LOG_INFO(item_cnt);
          
            auto rece_vec = NPOT::Receive(client,pp,vec_select_bit,item_cnt);
           
            uint64_t sum = 0;
            for(auto x: rece_vec){
                uint64_t temp = Block::BlockToInt64(x);
                sum += temp;
                sum &= 0xFFFFFFFF;
            }
            client.SendInteger(sum);
            client.SendInteger(Card);
            APSU_LOG_INFO("card"<<Card);
            ECGroup_Finalize(); 
            Global_Finalize();   
            all_timer.setTimePoint("Cardsum_finish");
        }

#endif

    } // namespace receiver
} // namespace apsu
