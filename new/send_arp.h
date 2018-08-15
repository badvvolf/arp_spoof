
#pragma once
#include "pcap_manager.h"

#include <pcap.h>
#include <stdio.h>
#include <netinet/ether.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h> 
#include <sys/time.h>
#include "typedef.h"
#include <mutex>


//전방 선언
class PcapManager;

extern mutex subMutex;
extern mutex sendMutex;


//--- Struct definition ---

#pragma pack(push, 1) 

typedef struct ARPPacket{

    struct ether_header eth;
    ARPHDR arp;

}ARPPACKET;


#pragma pack(pop)


//___ Struct definition ___


class SendARP
{

private:

    PcapManager * pcapManager;

  
    uint8_t packet[100];

    ARPPACKET buf;

    bool gotTargetMAC = false;


    bool gotSenderMAC = false;
    bool isBuilt = false;

    void SetMyAddr(uint8_t * );
    bool MakeARP(uint8_t , ARPPACKET * , uint8_t * , uint8_t * , uint32_t , uint32_t );
    void MakeEtherHeader(struct ether_header * , uint8_t * , uint8_t * ); 
    bool RequestSenderMAC();
 
    bool ARPRequest(uint32_t requestWho);

public:
  uint8_t myMAC[ETH_ALEN];
       uint8_t senderMAC[ETH_ALEN];
    uint32_t myIP;
    uint32_t senderIP;
    uint32_t targetIP;
    uint8_t * interface;

    uint8_t targetMAC[ETH_ALEN];
    

    SendARP(uint8_t * , uint32_t, uint32_t, PcapManager * );
   // ~SendARP();
    void SetSenderMAC(uint8_t *);
    bool InfectARPTable();
    void SetTargetMAC(uint8_t * tMAC);


};