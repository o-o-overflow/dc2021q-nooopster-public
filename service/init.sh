#!/bin/bash
set -x
if [[ "$1" != "tini" ]]; then
	exec /tini -- /bin/bash $0 tini
fi

set -e
mount -t proc proc proc/
mount -t sysfs sys sys/

ifconfig eth0 10.0.2.15 netmask 255.255.255.240 broadcast 10.0.2.15
ifconfig lo 127.0.0.1 netmask 255.0.0.0
route add default gw 10.0.2.2

openvpn --verb 9 \
	--dev tun \
	--local 10.0.2.15 \
	--port 1999 \
	--proto tcp4-server \
	--secret /openvpn.shared.key \
	--ifconfig 192.168.5.1 192.168.5.2 \
	--persist-tun \
	--user openvpn --group openvpn \
	--chroot /var/lib/openvpn/chroot \
	--daemon

# socat TCP4-LISTEN:1999,bind=10.0.2.15 SYSTEM:/bin/bash
# echo "hello there" | nc -l 0.0.0.0 1999
# /echoserver.py 1999 &
# nc -l 0.0.0.0 1999 &

# setcap 'cap_net_bind_service=+ep' /usr/sbin/dnsmasq
exec supervisord -n -c /supervisord.conf
