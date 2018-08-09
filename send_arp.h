
#pragma once
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
#include <linux/ip.h>
#include <unistd.h>
#include <stdlib.h> 
#include <sys/time.h>
#include "pcap_manager.h"

//--- Struct definition ---

#pragma pack(push, 1) 
typedef struct ARPHdr
{
    uint16_t hardType;		
    uint16_t protoType;	
    uint8_t hardLen;		
    uint8_t protoLen;		
    uint16_t opcode;		

    uint8_t srcMAC[ETH_ALEN];	
    uint32_t srcIP;		
    uint8_t dstMAC[ETH_ALEN];	
    uint32_t dstIP;

}ARPHDR;


typedef struct ARPPacket{

    struct ether_header eth;
    ARPHDR arp;

}ARPPACKET;


#pragma pack(pop)


//___ Struct definition ___

enum class Len
{
    ETHERLEN = 14,
    IPADDRLEN = 4,
    PACKETLEN = 0x2a
};

class SendARP
{

private:

    PcapManager * pcapManager;

    uint8_t myMAC[ETH_ALEN];
    uint8_t senderMAC[ETH_ALEN];
    uint32_t myIP;
    uint32_t senderIP;
    uint32_t targetIP;
    uint8_t * interface;

    bool isBuilt = false;

    void SetMyAddr(uint8_t * );
    bool MakeARP(uint8_t , ARPPACKET * , uint8_t * , uint8_t * , uint32_t , uint32_t );
    void MakeEtherHeader(struct ether_header * , uint8_t * , uint8_t * );
 
    bool IsARPNext(uint16_t );
    bool IsSenderIP(uint32_t );

    bool GetSenderMAC(uint8_t *);
 
  

public:
   
    bool MaintainInfection();
    SendARP(uint8_t * , uint32_t, uint32_t, PcapManager * );
   // ~SendARP();

    bool InfectARPTable();
};