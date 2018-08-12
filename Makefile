all : send_arp

send_arp: send_arp.o pcap_manager.o
	g++ -g -o send_arp send_arp.o pcap_manager.o -lpcap -lpthread

send_arp.o:
	g++ -g -c -o send_arp.o send_arp.cpp

pcap_manager.o:
	g++ -g -c -o pcap_manager.o pcap_manager.cpp

clean:
	rm -f send_arp
	rm -f *.o

