
#pragma once
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>

class PcapManager
{

private:
    
    pcap_t * handle;
    uint8_t errbuf[PCAP_ERRBUF_SIZE];


public:
    PcapManager(uint8_t * );
    void Send(uint8_t * buf, int32_t len);
   
    void StartReceiver();


    void AddReceiverItem();
    


};