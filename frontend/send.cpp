#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <numeric>
#include <cryptoTools/Common/Timer.h>

#include <iomanip>
#include <iostream>


#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include <cryptoTools/Common/Defines.h>

using namespace osuCrypto;
using namespace std;
#include <string.h>

int main(){
    std::vector<std::array<oc::block, 2>> sendMessages;
    sendMessages.resize(10);
    for(int i=0;i<10;i++){
        sendMessages[i]={oc::toBlock(i),oc::toBlock(1)};
    }
    int numThreads = 5;
    oc::IOService ios;
    oc::Session  ep0(ios, "localhost:59999", oc::SessionMode::Client);
    oc::PRNG prng(oc::sysRandomSeed());
    std::vector<osuCrypto::Channel> chls(numThreads);

    
    for (int i = 0; i < numThreads; ++i)
        chls[i] = ep0.addChannel();
    std::vector<oc::IknpOtExtSender> senders(numThreads);
    
    senders[0].sendChosen(sendMessages, prng, chls[0]);
    cout<<"??"<<endl;
    int recv_num = chls[0].getTotalDataRecv();
    int send_num = chls[0].getTotalDataSent();

    cout<<(recv_num)/1024<<"KB";


}