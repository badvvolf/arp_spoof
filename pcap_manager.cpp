
#pragma once
#include "pcap_manager.h"


PcapManager::PcapManager(uint8_t * interface)
{
    handle = pcap_open_live((const char *)interface, BUFSIZ, 1, 500, (char *)errbuf);
    if (handle == NULL) 
    {
        fprintf(stderr, "couldn't open device %s: %s\n", interface, errbuf);
        exit(1);
    }

}

void PcapManager::Send(uint8_t * buf, int32_t len)
{
    pcap_sendpacket(handle, (const u_char *)buf, len);


}



void PcapManager::StartReceiver()
{

    struct pcap_pkthdr * header;
    const uint8_t * packet;

    while(true)
    {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;


    }
}





