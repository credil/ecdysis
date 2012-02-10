#!/bin/bash

#IPV4_ADDR="x.x.x.x"
PREFIX_ADDR="64:ff9b::"
PREFIX_LEN="96"

echo "**************"
echo "nf_nat64 setup"
echo "**************"

if [[ ! -z $1 ]]; then
	IPV4_ADDR=$1;
fi

if [[ -z $IPV4_ADDR ]]; then
	echo "Trying to guess the nat64 IPv4 address..."; echo
	GUESS_IPV4_IF=$(ip route show | grep default | head -1 | sed -r 's/.+dev ([^ ]+) .+/\1/')
	GUESS_PRIMARY_IPV4=$(ip addr show primary | grep "inet " | awk '{print $2}' | sed -r 's/\/[0-9]+$//' | tail -1)

	if [[ "$GUESS_PRIMARY_IPV4" == "" ]]; then
		echo "Error: No IPv4 address found with default route found."
		exit 1
	fi

	echo "Warning: Using a non-dedicated IPv4 address. NAT64 will partially work if you choose to continue with \"$GUESS_PRIMARY_IPV4\".  See KNOWN_ISSUES for further information."
	echo
	echo "However, you can define a dedicated IPv4 address with:"
	echo "# ifconfig eth0:1 w.x.y.z up"
	echo "and run this script again:"
	echo "# ./nat64-config.sh w.x.y.z"
	echo "Ctrl-c to abort. Any other key will continue."
	read i
	IPV4_ADDR=$GUESS_PRIMARY_IPV4
fi

: ${IPV4_ADDR:?}


echo
echo "Info: Using $IPV4_ADDR as the NAT64 IPv4 address."
echo "Info: Using ${PREFIX_ADDR}/${PREFIX_LEN} as the NAT64 Prefix."

# Must have a global scope ipv6 address
if [[ $(ip -6 addr show scope global | grep inet6 | wc -l) == 0 ]]; then
	echo "No global scope ipv6 address!"
	exit 1
fi

echo 
echo

set -ex

# Load the nf_nat64 module
modprobe -r nf_nat64
modprobe nf_nat64 nat64_ipv4_addr=$IPV4_ADDR nat64_prefix_addr=$PREFIX_ADDR nat64_prefix_len=$PREFIX_LEN

# Enable the nat64 network interface
ifconfig nat64 up

# Install the route to the nat64 prefix
ip -6 route add ${PREFIX_ADDR}/${PREFIX_LEN} dev nat64

# Enable ipv6 and ipv4 forwarding
sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.forwarding=1

