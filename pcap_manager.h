
#pragma once
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <vector>
#include <string.h>
#include <netinet/ether.h>
#include <thread>         // std::thread
#include <netinet/ip.h>
#include "send_arp.h"


using namespace std;


enum class SUBTYPE
{
    ARPMANAGER =0,
    GETSENDERMAC = 1

};

class Subscriber
{
public:
   /* enum class PROTO
    {
        USEETHERSRC = 0x00000001, 
        USEETHERDST = 0x00000002,
        USIPSRC     = 0x00000004,
        USIPDST     = 0x00000008,
        USEARPSENDR = 0x00000010,
        USEARPTARGET = 0x00000020
    };
*/
    

    uint32_t type;
  
    void * subObj;

    uint32_t config;
    uint32_t proto;


    uint8_t eth_src[6];
    uint8_t eth_dst[6];
    uint32_t ip_src;
    uint32_t ip_dst;
    uint8_t arp_sender[6];
    uint8_t arp_target[6];
    uint32_t arp_senderIP;
    uint32_t arp_targerIP;
    
   Subscriber(/*uint32_t cf, */
        uint8_t * ethSrc, uint8_t * ethDst, uint32_t ipSrc, 
                uint32_t ipDst, uint8_t * arpSender, uint8_t * arpTarget, 
                uint32_t subtype, void *, uint32_t proto);
    Subscriber();
};


class PcapManager
{

private:
    
    pcap_t * handle;
    uint8_t errbuf[PCAP_ERRBUF_SIZE];
    vector <Subscriber *> subscriber;

public:
    PcapManager(uint8_t * );
    ~PcapManager();
    void Send(uint8_t * buf, int32_t len);
   
    void StartReceiver();


    void AddSubscriber(Subscriber * sub);
    void NoticeSubscriber(Subscriber * sub, const uint8_t * );
    Subscriber *  FindSubscriber(const uint8_t * packet);

};