#pragma once
#include "send_arp.h"
#include "pcap_manager.h"
#include <list>


class Attack
{

public:
    SendARP * sendArp;
    uint32_t relaySubId;
    uint32_t requestSubId1;
    uint32_t requestSubId2;


    thread * maintain;



    Attack(uint8_t * interface, uint32_t senderIP, uint32_t targetIP, PcapManager *pcapManager);

};



class ARPSpoof
{

private:
    list <Attack *> attackList;
    list <uint32_t> subID;

    PcapManager * pcapManager;
    uint8_t * interface;



public:

    void AddAttackList(uint32_t senderIP, uint32_t targetIP);
    void RelayIPPacket(const uint8_t * buf, uint32_t len, uint32_t subID);
    void AttackStart();
    void ReactRequest(uint32_t subID);
    ARPSpoof(uint8_t * interface);
    void MaintainInfection(SendARP * sendARP);

};

