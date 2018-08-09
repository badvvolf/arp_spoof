#include <stdio.h>
#include "arp_spoof.h"

/*
[프로그램]
arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]
ex : arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2

[상세]

오늘 배운 "ARP spoofing의 모든 것" PPT 숙지할 것.

코드에 victim, gateway라는 용어를 사용하지 말고 반드시 sender, target(혹은 receiver)라는 단어를 사용할 것.

sender에서 보내는 spoofed IP packet을 attacker가 수신하면 이를 relay하는 것 코드 구현.

sender에서 infection이 풀리는 시점을 정확히 파악하여 재감염시키는 코드 구현.

주기적으로 ARP injection packet을 날리는 코드 구현.

코딩 능력이 된다면 (sender, target) 세션을 여러개 처리할 수 있도록 코드 구현.

*/

int main(int argc, char * argv[])
{

    if(argc < 4)
    {
        printf("usage : arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
        return 1;
    }




   

}

