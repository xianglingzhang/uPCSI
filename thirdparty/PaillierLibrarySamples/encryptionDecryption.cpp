#include <assert.h>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <gmp.h>
#include <string>
#include <chrono>

#include "paillier.h"

int main(int argc, char *argv[])
{
    // // Security parameter (number of bits of the modulus)
    // const long n = 256;   
    
    // // Generate public and secret keys
    // paillier_pubkey_t* pubKey;
    // paillier_prvkey_t* secKey;
    // paillier_keygen(n, &pubKey, &secKey, paillier_get_rand_devurandom);

    // // Plaintext initialization
    // paillier_plaintext_t* m;
    // m = paillier_plaintext_from_ui(2);
    // gmp_printf("Plaintext: %Zd\n", m);

    // // Encrypt the message
    // paillier_ciphertext_t* ctxt;
    // ctxt = paillier_enc(NULL, pubKey, m, paillier_get_rand_devurandom);
    // gmp_printf("Ciphertext: %Zd\n", ctxt);

    // // Decrypt the ciphertext
    // paillier_plaintext_t* dec;
    // dec = paillier_dec(NULL, pubKey, secKey, ctxt);
    // gmp_printf("Decrypted: %Zd\n", dec);

    // // Cleaning up
    // paillier_freepubkey(pubKey);
    // paillier_freeprvkey(secKey);
    // paillier_freeplaintext(m);
    // paillier_freeplaintext(dec);
    // paillier_freeciphertext(ctxt);

    const long n = 1024;   
    paillier_pubkey_t* pubKey;
    paillier_prvkey_t* secKey;
    char* mchar1 = "d43c176374ead4ed";
    char* mchar2 = "71aa294407501067";
    paillier_plaintext_t* message1 = paillier_plaintext_from_bytes(mchar1, 16);
    paillier_plaintext_t* message2 = paillier_plaintext_from_bytes(mchar2, 16);
    // paillier_plaintext_t* message1 = paillier_plaintext_from_ui(4294967296);
    // paillier_plaintext_t* message2 = paillier_plaintext_from_ui(4294967290);
    // gmp_randstate_t rand;
    // gmp_randinit_mt(rand);
    // gmp_randseed_ui(rand, 100000U);
    // mpz_init(message->m);
    // mpz_urandomb(message->m, rand, 32);
    gmp_printf("Plaintext1: %Zd\n", message1);
    gmp_printf("Plaintext2: %Zd\n", message2);

    auto start_time = std::chrono::steady_clock::now(); 
    paillier_keygen(n, &pubKey, &secKey, paillier_get_rand_devurandom);
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "average key generation takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    gmp_printf("pubKey: %Zd\n", pubKey->n);
    gmp_printf("secKey: %Zd\n", secKey->lambda);

    start_time = std::chrono::steady_clock::now(); 
    paillier_ciphertext_t* ctxt1 = paillier_enc(NULL, pubKey, message1, paillier_get_rand_devurandom);
    paillier_ciphertext_t* ctxt2 = paillier_enc(NULL, pubKey, message2, paillier_get_rand_devurandom);
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average encryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count()/2 << " ms" << std::endl;

    start_time = std::chrono::steady_clock::now(); 
    paillier_plaintext_t* dec = paillier_dec(NULL, pubKey, secKey, ctxt1);
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average decryption takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;
    gmp_printf("Decrypted: %Zd\n", dec);

    paillier_ciphertext_t* encrypted_sum = paillier_create_enc_zero();
    start_time = std::chrono::steady_clock::now(); 
    paillier_mul(pubKey, encrypted_sum, ctxt1, ctxt2);
    end_time = std::chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    std::cout << "average homomorphic add takes time = " 
    << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    dec = paillier_dec(NULL, pubKey, secKey, encrypted_sum);
    gmp_printf("Decrypted: %Zd\n", dec);

    // std::fstream pubKeyFile("pk.txt", std::fstream::in);
    // std::fstream secKeyFile("sk.txt", std::fstream::in);    
    
    // assert(pubKeyFile.is_open());
    // assert(secKeyFile.is_open());    

    // std::string hexPubKey;
    // std::string hexSecKey;    
    // std::getline(pubKeyFile, hexPubKey);
    // // std::cout << hexPubKey << std::endl;
    // std::getline(secKeyFile, hexSecKey);    

    // pubKeyFile.close();
    // secKeyFile.close(); 

    // paillier_pubkey_t* pubKey = paillier_pubkey_from_hex(&hexPubKey[0]);
    // std::cout << pubKey->bits << std::endl;
    // paillier_prvkey_t* secKey = paillier_prvkey_from_hex(&hexSecKey[0], pubKey);  

    // // gmp_printf("pubKey: %Zd\n", pubKey);
    // // gmp_printf("secKey: %Zd\n", secKey);

    // char* mchar1 = "ABCDEFGHI@JKLMNO";
    // char* mchar2 = "20202020202020202020202020202020";
    // // paillier_plaintext_t* message1 = paillier_plaintext_from_bytes(mchar1, 16);
    // paillier_plaintext_t* message1 = paillier_plaintext_from_ui(86743875649080752286440200822480240442);
    // paillier_plaintext_t* message2 = paillier_plaintext_from_bytes(mchar2, 32);

    // gmp_printf("Plaintext1: %Zd\n", message1);
    // gmp_printf("Plaintext2: %Zd\n", message2);

    // paillier_ciphertext_t* ctxt1 = paillier_enc(NULL, pubKey, message1, paillier_get_rand_devurandom);
    // paillier_ciphertext_t* ctxt2 = paillier_enc(NULL, pubKey, message2, paillier_get_rand_devurandom);

    // // gmp_printf("computed Cyphertext1: %Zd\n", ctxt1);
    // gmp_printf("computed Cyphertext2: %Zd\n", ctxt1);

    // // char* byteCtxt = (char*)paillier_ciphertext_to_bytes(512, ctxt1);
    // // printf("%s\n", byteCtxt);

    // // char* m1 = "1fb7f08a42deb47876e4cbdc3f0b172c033563a696ad7a7c76fa5971b793fa488dcdd6bd65c7c5440d67d847cb89ccca468b2c96763fff5a5ece8330251112d65e59b7da94cfe9309f441ccc8f59c67dec75113d37b1ee929c8d4ce6b5e561a30a91104b0526de892e4eff9f4fbecba3db8ed94267be31df360feaffb1151ef5b5a8e51777f09d38072bcb1b1ad15d80d5448fd0edb41cc499f8eebae2af26569427a26d0afeaa833173d6ae4e5f84eb88c0c68c29baecf7ec5af2c1c5577336ca9482690f1c94597654afda84c6fb74df95cdd08fa9a66296126b4061b0530d124f3797426a08f72e90ef4994eeb348f5e92bd12d41cd3343a9e271a2f73d2cc7ffbd65bf64fb63e759f312e615aae01ae9f4573a21f1a70f56a61cfbb94d8f96fcf06c2b3216ed9574f6888df86cd5e471b641507ac6815ca781f6d31e69d6848e542a7c57dc21109b5574b63365a19273783fafc93639c414b9475ea5ea82e73958ff5fdba967d52721ff71209e5a3db3c580e1bfd142ba4b8ab77eb16cb488d46a04a672662cd108b7e9c58ba13dfb850653208f81956539475ffce85e0b0da59e5bd8d90051be9b2cc99e37c060ce09814e1524458bfb5427d7a16b672682be448fa16464fcb3e7f1dca6812a2c5a9814b98ccb676367b7b3b269c670cd0210edf70ad9cb337f766af75fe06d18b3f7f7c2eae6565ff2815c2c09b1a1f5";
    // // char* m2 = "61803645f2798c06f2c08fc254eee612c55542051c8777d6ce69ede9c84a179afb2081167494dee727488ae5e9b56d98f4fcf132514616859fc854fbd3acf6aecd97324ac3f2affa9f44864a9afc505754aa3b564b4617e887d6aa1f88095bccf6b47f458566f9d85e80fcd478a58d4c2e895d0ed428aa8919d8ce752472bdc704fe9f01b1f663e3a9defca4b3847134883d5433b6bebb7d5a0358bcc8e3385cdf8787a1c78165eb03fc295c2ee93809d7a7a4689e79faf173e4ca3d0a6a9175887d0c70b35c529aa02699c4d4e8c98a9f3b8f2be41f35905adebf8a6940a93875d1e24e578a93bdb7cbf66cd3cdb736466588649ac237d55121ce0c0d18bc5da660d8faf9f0849ed1775ffcc5edb6900ebfb6c1e33459d29655edf706324cf642c8f36433d6b850a43ee0e788e120737b8a2858d1b5302bad3413102fd7dccfe458b257fdbf920fe942e23ec446b1b302d41710fe56b26e11987ac06cfa635664c7a0ec18f8c8c871919fc893a3117ff5e73d4c115e66e3bc5bd2b9127b2bb816c549245c65cf22a533a3d2b6cb7c46757d3a87173f93e8b431891697f8d60c59631734f46cf3d70d9065f0167d5ad7353c0812af024ced593273551d29c89232f2f3d548b9248291c1b8e833ed178eb2cf1ad6f1d6864f1fd3e2e3937e00d391ad330b443aec85528571740ed5538188c32caab27c7bf437df2bb97cb90e02";
    // // paillier_plaintext_t* me1 = paillier_plaintext_from_bytes(m1, 128);
    // // gmp_printf("real Cyphertext1: %Zd\n", me1);
    // // paillier_plaintext_t* me2 = paillier_plaintext_from_bytes(m1, 128);
    
    
    // // printf("%s\n", byteCtxt2);

    // paillier_plaintext_t* dec1 = paillier_dec(NULL, pubKey, secKey, ctxt1);
    // gmp_printf("Decrypted: %Zd\n", dec1);
    // // paillier_plaintext_t* dec2 = paillier_dec(NULL, pubKey, secKey, ctxt2);
    // // gmp_printf("Decrypted: %Zd\n", dec2);

    // // char* bytePtxt = (char*)paillier_plaintext_to_bytes(16, dec1);
    // // printf("%s\n", bytePtxt);

    // // char* byteCtxt1 = (char*)paillier_ciphertext_to_bytes(512, ctxt1);
    // // // char* byteCtxt2 = (char*)paillier_ciphertext_to_bytes(128, ctxt2);
    // // printf("%s\n", byteCtxt1);
    
    // // char* m1 = "1fb7f08a42deb47876e4cbdc3f0b172c033563a696ad7a7c76fa5971b793fa488dcdd6bd65c7c5440d67d847cb89ccca468b2c96763fff5a5ece8330251112d65e59b7da94cfe9309f441ccc8f59c67dec75113d37b1ee929c8d4ce6b5e561a30a91104b0526de892e4eff9f4fbecba3db8ed94267be31df360feaffb1151ef5b5a8e51777f09d38072bcb1b1ad15d80d5448fd0edb41cc499f8eebae2af26569427a26d0afeaa833173d6ae4e5f84eb88c0c68c29baecf7ec5af2c1c5577336ca9482690f1c94597654afda84c6fb74df95cdd08fa9a66296126b4061b0530d124f3797426a08f72e90ef4994eeb348f5e92bd12d41cd3343a9e271a2f73d2cc7ffbd65bf64fb63e759f312e615aae01ae9f4573a21f1a70f56a61cfbb94d8f96fcf06c2b3216ed9574f6888df86cd5e471b641507ac6815ca781f6d31e69d6848e542a7c57dc21109b5574b63365a19273783fafc93639c414b9475ea5ea82e73958ff5fdba967d52721ff71209e5a3db3c580e1bfd142ba4b8ab77eb16cb488d46a04a672662cd108b7e9c58ba13dfb850653208f81956539475ffce85e0b0da59e5bd8d90051be9b2cc99e37c060ce09814e1524458bfb5427d7a16b672682be448fa16464fcb3e7f1dca6812a2c5a9814b98ccb676367b7b3b269c670cd0210edf70ad9cb337f766af75fe06d18b3f7f7c2eae6565ff2815c2c09b1a1f5";
    // // printf("%s\n", m1);
    // std::fstream message1File("message1.txt", std::fstream::in);

    // assert(message1File.is_open());

    // std::string c1;
    // std::getline(message1File, c1);

    // message1File.close();

    // std::cout << "Message 1: " << c1 << std::endl;

    // paillier_plaintext_t* me1 = paillier_plaintext_from_bytes(const_cast<char *>(c1.data()), 512);
    // gmp_printf("real Cyphertext1: %Zd\n", me1);

    return 0;
}
