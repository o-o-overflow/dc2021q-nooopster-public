#!/bin/bash

export TMP=/

if [[ ! -e ${UML_ROOT}/dev/net/tun ]]; then
	cp -r /dev ${UML_ROOT}
	mkdir -p ${UML_ROOT}/dev/net
	mknod ${UML_ROOT}/dev/net/tun c 10 200
	mkdir -p ${UML_ROOT}/root/.uml
fi

export HOST_IP=$(hostname -i)

# exec chroot --userspec=uml ${UML_ROOT} \
# /tini -p SIGTERM \
# /usr/bin/socat TCP4-LISTEN:${INTERNAL_SERVICE_PORT} EXEC:/bin/bash &
# exit 0

exec chroot --userspec=uml ${UML_ROOT} \
/linux rootflags= rootfstype=hostfs rw mem=64M eth0=slirp,,/slirp.sh init=/init.sh  \
1>/dev/null 2>/dev/null

# exec ${UML_ROOT}/linux rootflags=${UML_ROOT} rootfstype=hostfs rw mem=32M eth0=slirp,,${UML_ROOT}/slirp.sh init=/init.sh  \
# 1>/dev/null 2>/dev/null
