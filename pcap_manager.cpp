

#pragma once
#include "pcap_manager.h"

mutex subMutex;
mutex sendMutex;

uint32_t Subscriber::subIDCount = 0;

Subscriber::Subscriber()
{
    //아무것도 안 함

}

Subscriber::Subscriber(uint8_t * ethSrc, uint8_t * ethDst, 
                        uint32_t ipSrc, uint32_t ipDst,
                        uint8_t * arpSender, uint8_t * arpTarget,
                        uint32_t arpSenderIP, uint32_t arpTargetIP,
                        uint32_t subtype, void* obj, uint32_t pro, void * cb)
{
    type = subtype;

    switch(type)
    {
    case (uint32_t)SUBTYPE::GETSENDERMAC:
        
        memcpy(eth_dst, ethDst, ETH_ALEN);
        arp_senderIP = arpSenderIP;
        break;
    case (uint32_t)SUBTYPE::RELAYIP:

        memcpy(eth_dst, ethDst, ETH_ALEN);
        memcpy(eth_src, ethSrc, ETH_ALEN);
     //   ip_src = ipSrc;
        ip_dst = ipDst;
        
        break;

    case (uint32_t)SUBTYPE::REACTSENDERREQUEST:

        memcpy(eth_src, ethSrc, ETH_ALEN);       
        memcpy(arp_sender, arpSender, ETH_ALEN);
        arp_senderIP = arpSenderIP;
        arp_targetIP = arpTargetIP;
        break;

    
    case (uint32_t)SUBTYPE::REACTTARGETREQUEST:

        memcpy(eth_src, ethSrc, ETH_ALEN);       
        memcpy(arp_sender, arpSender, ETH_ALEN);
        arp_senderIP = arpSenderIP;
        break;
        
    }
    
    subObj = obj;
    proto = pro;
    callback = cb;

    id = subIDCount;
    subIDCount ++;

}



uint32_t Subscriber::GetSubID()
{
    return id;

}


PcapManager::PcapManager(uint8_t * interface)
{
    handle = pcap_open_live((const char *)interface, BUFSIZ, 1, 0, (char *)errbuf);
    if (handle == NULL) 
    {
        fprintf(stderr, "couldn't open device %s: %s\n", interface, errbuf);
        exit(1);
    }


    thread receiver(&PcapManager::StartReceiver, this);
    receiver.detach();

}



void PcapManager::ReleaseSubcriber(Subscriber * sub)
{
    list<Subscriber *>::iterator itor;

    itor=find(subscriber.begin(), subscriber.end(), sub);
    subscriber.erase(itor);
}



void PcapManager::Send(uint8_t * buf, int32_t len)
{
    unique_lock<mutex> sendMutexLock(sendMutex);
    pcap_sendpacket(handle, (const u_char *)buf, len);
    sendMutexLock.unlock();
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

        unique_lock<mutex> subMutexLock(subMutex);

        //등록된 아이템일시 알람
        if( (sub = FindSubscriber(packet)) != NULL)
        {
            NoticeSubscriber(sub, packet, header->len);
        }
        
    }
}

void PcapManager::NoticeSubscriber(Subscriber * sub, const uint8_t * packet, uint32_t len)
{
    //구독자한테 알람
    switch(sub->type)
    {
    case (uint32_t)SUBTYPE::GETSENDERMAC:
        {
            ARPHDR * arp =  (ARPHDR *)((uint8_t *)packet + (uint8_t)LEN::ETHERLEN);

            FPSETSENDERMAC fpSetSenderMAC = (FPSETSENDERMAC)sub->callback;
            fpSetSenderMAC((SendARP *)(sub->subObj), arp->srcMAC);

            break;
        }
    case (uint32_t)SUBTYPE::RELAYIP:
        {

            FPRELAYIPPACKET fpRelayIpPacket = (FPRELAYIPPACKET)sub->callback;
            fpRelayIpPacket((ARPSpoof *)(sub->subObj), packet, len, sub->id);
            break;
        }
    case (uint32_t)SUBTYPE::REACTSENDERREQUEST:
        {

            FPREACTREQUEST fpReactRequest = (FPREACTREQUEST)sub->callback;
            fpReactRequest((ARPSpoof *)(sub->subObj), sub->id);
            break;

            
        }
    case (uint32_t)SUBTYPE::REACTTARGETREQUEST:
        {

            FPREACTREQUEST fpReactRequest = (FPREACTREQUEST)sub->callback;
            fpReactRequest((ARPSpoof *)(sub->subObj), sub->id);
            break;

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
        packetInfo.arp_targetIP = arp->dstIP;

        break;

    case ETHERTYPE_IP:
      {
        packetInfo.proto = ETHERTYPE_IP;

        ipInfo = (ip *)((u_int8_t *)eth + (u_int8_t)LEN::ETHERLEN);
        packetInfo.ip_src = ipInfo->ip_src.s_addr;
        packetInfo.ip_dst = ipInfo->ip_dst.s_addr;
      

        break;
      }
    default:
        return NULL;  

    }
    
    memcpy(packetInfo.eth_src , eth->ether_shost, ETH_ALEN);
    memcpy(packetInfo.eth_dst, eth->ether_dhost, ETH_ALEN);

    list<Subscriber *>::iterator itor;

    for (itor=subscriber.begin(); itor != subscriber.end(); itor++ )
    {
        
        if((*itor)->proto != packetInfo.proto)
            continue;
        

        switch((*itor)->type)
        {
        case (uint32_t)SUBTYPE::GETSENDERMAC :
                
            if(memcmp((*itor)->eth_dst, packetInfo.eth_dst, ETH_ALEN))
                continue;
            
            if((*itor)->arp_senderIP != packetInfo.arp_senderIP)
                continue;
            
            return (*itor);    

        case (uint32_t)SUBTYPE::RELAYIP :
            
            if(memcmp((*itor)->eth_dst, packetInfo.eth_dst, ETH_ALEN))
                    continue;
            
            if(memcmp((*itor)->eth_src, packetInfo.eth_src, ETH_ALEN))
                    continue;              

            //내 IP가 목적지인 경우 넘기지 않음
            if((*itor)->ip_dst == packetInfo.ip_dst)
                    continue;
            
            return (*itor); 
            

        case (uint32_t)SUBTYPE::REACTSENDERREQUEST :
            
            if(memcmp((*itor)->eth_src, packetInfo.eth_src, ETH_ALEN))
                   continue;
            if(memcmp((*itor)->arp_sender, packetInfo.arp_sender, ETH_ALEN))
                 continue;
            if((*itor)->arp_senderIP != packetInfo.arp_senderIP)
                 continue;

            if((*itor)->arp_targetIP != packetInfo.arp_targetIP)
                 continue;

            return (*itor);    
            
        case (uint32_t)SUBTYPE::REACTTARGETREQUEST :
            
            if(memcmp((*itor)->eth_src, packetInfo.eth_src, ETH_ALEN))
                 continue;
            if(memcmp((*itor)->arp_sender, packetInfo.arp_sender, ETH_ALEN))
                 continue;
            if((*itor)->arp_senderIP != packetInfo.arp_senderIP)
                 continue;

            return (*itor);    


        }

        

    } //for (int i =0; i<subscriber.size(); i++)


   return NULL;
}


void PcapManager::AddSubscriber(Subscriber * sub)
{
   // unique_lock<mutex> subMutexLock(subMutex);
    subscriber.push_back(sub);
    //subMutexLock.unlock();
}



PcapManager::~PcapManager()
{
    list<Subscriber *>::iterator itor;

    for (itor=subscriber.begin(); itor != subscriber.end(); itor++)
    {

        delete(*itor);
    }
    /*
    for (int i =0; i<subscriber.size(); i++)
    {
        delete(subscriber[i]);
    }
*/
    subscriber.clear();

}



