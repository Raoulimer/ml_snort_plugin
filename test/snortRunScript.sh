#!/bin/bash

file="/etc/snort/snort.lua"

if [ ! -f "$file" ]; then
	echo "Error: $file does not exist or is not a regular file."
	exit 1
fi

get_active_interface() {
	ip route | grep '^default' | awk '{print $5}'
}

set_defaults() {
	read -p "Enter classifier_type (NN or XGB) [default=NN]: " classifier_type
	classifier_type=${classifier_type:-NN}

	read -p "Enter mal_threshold_perc [default=90]: " mal_threshold_perc
	mal_threshold_perc=${mal_threshold_perc:-90}

	read -p "Enter tt_expired [default=60]: " tt_expired
	tt_expired=${tt_expired:-60}

	read -p "Enter iteration_interval [default=20]: " iteration_interval
	iteration_interval=${iteration_interval:-20}

	# Get the active network interface
	active_interface=$(get_active_interface)
	read -p "Enter network interface [default=$active_interface]: " network_interface
	network_interface=${network_interface:-$active_interface}
}

# Prompt user for values
set_defaults

ml_classifiers="ml_classifiers={classifier_type='$classifier_type', mal_threshold_perc=$mal_threshold_perc, tt_expired=$tt_expired, iteration_interval=$iteration_interval }"

sed -i '$d' "$file"

echo "$ml_classifiers" >>"$file"

echo "Snort configuration updated"
sleep 1
echo "Running Snort"

sudo snort -c /etc/snort/snort.lua -R /etc/snort/rules/local.rules \
	-i $network_interface --plugin-path /usr/local/snort/lib/snort/plugins/alternative \
	--daq-dir /usr/lib/daq/ -A none
