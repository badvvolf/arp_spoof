#!/bin/bash

echo "Your network interface is..."

ifconfig

read -p "Choose interface: " interface

for ((i=0;;i++)); do
	read -p "What is sender ip?: " senderip[$i]
	read -p "What is target ip?: " targetip[$i]
	read -p "Want to set more ip?(Y/N): " getInput

	if [ "$getInput" == "N" ] || [ "$getInput" == "n" ]; then
		break	

	fi
done


startCmd="sudo ./arp_spoof ${interface} "

for ((i=0;i<${#senderip[*]};i++)); do
	startCmd+="${senderip[$i]} ${targetip[$i]} "
done

${startCmd}
