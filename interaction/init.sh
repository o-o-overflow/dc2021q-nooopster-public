#!/bin/bash -x
HOST=$1
PORT=$2
shift 2

echo "Host: $HOST $PORT"
echo "cmd: $@"

mount -t proc proc proc/
mount -t sysfs sys sys/

ifconfig eth0 10.0.2.15 netmask 255.255.255.240 broadcast 10.0.2.15
ifconfig lo 127.0.0.1 netmask 255.0.0.0
route add default gw 10.0.2.2

set -e
# --verb 9 \
openvpn --dev tun \
	--remote $HOST $PORT tcp-client \
	--secret openvpn.shared.key \
	--ifconfig 192.168.5.2 192.168.5.1 \
	--dhcp-option DNS 192.168.5.1 \
	--daemon
sleep 10
set +e
