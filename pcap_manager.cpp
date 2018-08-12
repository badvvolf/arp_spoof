

#include "pcap_manager.h"


Subscriber::Subscriber()
{
    //아무것도 안 함

}

Subscriber::Subscriber(/*uint32_t cf, */uint8_t * ethSrc, uint8_t * ethDst, uint32_t ipSrc, 
                        uint32_t ipDst, uint8_t * arpSender, uint8_t * arpTarget,
                        uint32_t subtype, void* object, uint32_t pro)
{
    type = subtype;

    switch(type)
    {
    case (uint32_t)SUBTYPE::GETSENDERMAC:
        
        
        memcpy(eth_dst, ethDst, 6);
        arp_senderIP = ipSrc;


    }
    
    subObj = object;
    proto = pro;

    printf("--------%x %x\n", eth_dst[1], eth_dst[2]);

}


PcapManager::PcapManager(uint8_t * interface)
{
    handle = pcap_open_live((const char *)interface, BUFSIZ, 1, 500, (char *)errbuf);
    if (handle == NULL) 
    {
        fprintf(stderr, "couldn't open device %s: %s\n", interface, errbuf);
        exit(1);
    }


    thread receiver(&PcapManager::StartReceiver, this);
    receiver.detach();

}

void PcapManager::Send(uint8_t * buf, int32_t len)
{
    pcap_sendpacket(handle, (const u_char *)buf, len);

}


void PcapManager::StartReceiver()
{

    struct pcap_pkthdr * header;
    const uint8_t * packet;
    Subscriber * sub;
    
    while(true)
    {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        //등록된 아이템일시 알람
        if( (sub = FindSubscriber(packet)) != NULL)
        {
            NoticeSubscriber(sub, packet);
        }
    }
}




Subscriber * PcapManager::FindSubscriber(const uint8_t * packet)
{
    Subscriber packetInfo;
    struct ether_header * eth = (struct ether_header *)packet;

    struct ip * ipInfo;
    ARPHDR * arp; 

    switch(ntohs(eth->ether_type))
    {

    case ETHERTYPE_ARP:

        packetInfo.proto = ETHERTYPE_ARP;

        arp =  (ARPHDR *)((u_int8_t *)eth + (u_int8_t)LEN::ETHERLEN);
        memcpy(packetInfo.arp_sender, arp->srcMAC, ETH_ALEN);
        memcpy(packetInfo.arp_target, arp->dstMAC, ETH_ALEN);
        packetInfo.arp_senderIP = arp->srcIP;
        packetInfo.arp_targerIP = arp->dstIP;

        break;

    case ETHERTYPE_IP:

        packetInfo.proto = ETHERTYPE_IP;

        ipInfo = (ip *)((u_int8_t *)eth + (u_int8_t)LEN::ETHERLEN);
        packetInfo.ip_src = ipInfo->ip_src.s_addr;
        packetInfo.ip_dst = ipInfo->ip_dst.s_addr;
    
        break;

    default:
        return NULL;  

    }
    
    memcpy(packetInfo.eth_src , eth->ether_shost, ETH_ALEN);
    memcpy(packetInfo.eth_dst, eth->ether_dhost, ETH_ALEN);




    for (int i =0; i<subscriber.size(); i++)
    {
        
        if(subscriber[i]->proto != packetInfo.proto)
            continue;
        

        switch(subscriber[i]->type)
        {
        case (uint32_t)SUBTYPE::GETSENDERMAC :
                
    
            if(memcmp(subscriber[i]->eth_dst, packetInfo.eth_dst, ETH_ALEN))
                continue;
            
            if(subscriber[i]->arp_senderIP != packetInfo.arp_senderIP)
                continue;
            return subscriber[i];            
            
        }

        

    } //for (int i =0; i<subscriber.size(); i++)


   return NULL;
}


void PcapManager::NoticeSubscriber(Subscriber * sub, const uint8_t * packet)
{
    //구독자한테 알람
    switch(sub->type)
    {
    case (uint32_t)SUBTYPE::GETSENDERMAC:

        ARPHDR * arp =  (ARPHDR *)((u_int8_t *)packet + (u_int8_t)LEN::ETHERLEN);
        ((SendARP *)(sub->subObj))->SetSenderMAC((uint8_t * )arp->srcMAC);
        break;



    }


}


void PcapManager::AddSubscriber(Subscriber * sub)
{
    subscriber.push_back(sub);
}



PcapManager::~PcapManager()
{
        
    for (int i =0; i<subscriber.size(); i++)
    {
        delete(subscriber[i]);
    }

    subscriber.clear();

}



