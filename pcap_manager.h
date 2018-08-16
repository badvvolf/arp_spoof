
#pragma once

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <list>
#include <algorithm>
#include <string.h>
#include <netinet/ether.h>
#include <thread>  
#include <netinet/ip.h>
#include <mutex>
#include <condition_variable>
#include "typedef.h"

using namespace std;

class SendARP;
class ARPSpoof;

enum class SUBTYPE
{
    GETSENDERMAC =0,
    RELAYIP = 1,
    REACTSENDERREQUEST =2,
    REACTTARGETREQUEST = 3

};


typedef void (*FPSETSENDERMAC)(void *, uint8_t *);
typedef void (*FPRELAYIPPACKET)(void *, const uint8_t * buf, uint32_t len, uint32_t subID);
typedef void (*FPREACTREQUEST)(void *, uint32_t);

class Subscriber
{
private:
   
public:
     static uint32_t subIDCount;
    uint32_t id;
    
    uint32_t type;
    void * callback;
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
    uint32_t arp_targetIP;
    
    
   Subscriber(uint8_t * ethSrc, uint8_t * ethDst, 
                uint32_t ipSrc, uint32_t ipDst,
                uint8_t * arpSender, uint8_t * arpTarget,
                uint32_t arpSenderIP, uint32_t arp_targetIP,
                uint32_t subtype, void* obj, uint32_t pro, void * cb);

    Subscriber();
    uint32_t GetSubID();
};


class PcapManager
{

private:
    
    pcap_t * handle;
    uint8_t errbuf[PCAP_ERRBUF_SIZE];
    list <Subscriber *> subscriber;

public:
    PcapManager(uint8_t * );
    ~PcapManager();
    void Send(uint8_t * buf, int32_t len);
    void StartReceiver();


    void AddSubscriber(Subscriber * sub);
    void ReleaseSubcriber(Subscriber * sub);
    void NoticeSubscriber(Subscriber * sub, const uint8_t * , uint32_t);
    Subscriber *  FindSubscriber(const uint8_t * packet);

};



