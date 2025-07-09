#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <numeric>
#include <cryptoTools/Common/Timer.h>
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include <iomanip>
#include <iostream>

//using namespace std;
#include <cryptoTools/Common/Defines.h>

using namespace osuCrypto;
using namespace std;
#include <string.h>

int main(){

    int numThreads = 5;
    osuCrypto::IOService ios;
    osuCrypto::Session  ep0(ios, "localhost:59999", osuCrypto::SessionMode::Server);
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    std::vector<osuCrypto::Channel> chls(numThreads);
    for (int i = 0; i < numThreads; ++i)
        chls[i] = ep0.addChannel();
    std::vector<osuCrypto::IknpOtExtReceiver> receivers(numThreads);
            
            // osuCrypto::DefaultBaseOT base;
            // std::array<std::array<osuCrypto::block, 2>, 128> baseMsg;
            // base.send(baseMsg, prng, chls[0], numThreads);
            // receivers[0].setBaseOts(baseMsg, prng, chls[0]);
            
    osuCrypto::BitVector choices(10);
    for(int i=0;i<8;i++){
        choices[i] = 1;
    }
    std::vector<osuCrypto::block> messages(10);
            
    receivers[0].receiveChosen(choices, messages, prng, chls[0]);
    for(auto i:messages){
        cout<<i.as<uint64_t>()[0]<<endl;
    }

}