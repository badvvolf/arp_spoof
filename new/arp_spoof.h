#pragma once
#include "send_arp.h"
#include "pcap_manager.h"
#include <list>


class Attack
{

public:
    SendARP * sendArp;
    uint32_t subID;

    Attack(uint8_t * interface, uint32_t senderIP, uint32_t targetIP, PcapManager *pcapManager);

};



class ARPSpoof
{

private:
    list <Attack *> attackList;
    list <uint32_t> subID;

    uint32_t attackNum;
    PcapManager * pcapManager;
    uint8_t * interface;

public:

    void AddAttackList(uint32_t senderIP, uint32_t targetIP);
    void RelayIPPacket(const uint8_t * buf, uint32_t len, uint8_t subID);
    void AttackStart();
    void ReactRequest();
    ARPSpoof(uint8_t * interface, uint32_t attackNum);
    void MaintainInfection(SendARP * sendARP);

};

