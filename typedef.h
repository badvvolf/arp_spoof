#pragma once
#include <stdint.h>
#include <netinet/ether.h>
#include <mutex>

#pragma pack(push, 1)


using namespace std;

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

#pragma pack(pop)

enum class LEN
{
    ETHERLEN = 14,
    IPADDRLEN = 4,
    PACKETLEN = 0x2a
};


