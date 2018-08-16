<p>프로그램 구조</p>
<ul>
<li>pcap_manager는 pcap 라이브러리 함수를 이용하여 send하거나 receive 하는 역할을 한다. </li>
<li>arp_spoof나 send_arp에서 네트워크로부터 얻어와야 하는 정보가 있다면, pcap_manager에 구독(subscribe) 신청을 한다. </li>
<li>pcap_maanager가 자신의 구독 리스트에 등록된 패킷을 만나면, 구독과 함께 등록해 둔 callback 함수를 호출하여 각 클래스에게 알려준다.</li>
<li>send_arp는 arp 패킷을 만들고 보내는 역할을 하며, arp_spoof는 세션을 총괄하고, IP 패킷 relay나 sender 혹은 target의 request에 반응하는 역할을 한다. </li>

</ul>
