all : arp_spoof

arp_spoof: arp_spoof.o send_arp.o pcap_manager.o main.o
	g++ -g -o arp_spoof arp_spoof.o send_arp.o pcap_manager.o main.o -lpcap -lpthread

main.o:
	g++ -g -c -o main.o main.cpp

arp_spoof.o:
	g++ -g -c -o arp_spoof.o arp_spoof.cpp

send_arp.o:
	g++ -g -c -o send_arp.o send_arp.cpp

pcap_manager.o:
	g++ -g -c -o pcap_manager.o pcap_manager.cpp

clean:
	rm -f arp_spoof
	rm -f *.o

