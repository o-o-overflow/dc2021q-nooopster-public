#!/bin/bash
export TMP=/

if [[ ! -e /dev/net/tun ]]; then
	mkdir -p /dev/net
	mknod /dev/net/tun c 10 200
	# mkdir -p /root/.uml
fi

UML_TEMP=$$

HOST=$1
PORT=$2
shift 2

echo "#!/bin/bash -x" > /tmp/uml_launch.$UML_TEMP
echo "/init.sh $HOST $PORT" >> /tmp/uml_launch.$UML_TEMP
echo "/bin/bash -c \"$@\"" >> /tmp/uml_launch.$UML_TEMP
echo "echo \$? > /tmp/uml_exit_code.$UML_TEMP" >> /tmp/uml_launch.$UML_TEMP
echo "halt -f" >> /tmp/uml_launch.$UML_TEMP
chmod +x /tmp/uml_launch.$UML_TEMP

/linux rootflags=/ rootfstype=hostfs rw mem=128M eth0=slirp,,slirp-fullbolt init=/tmp/uml_launch.$UML_TEMP con1=fd:0,fd:1
RESULT=$(cat /tmp/uml_exit_code.$UML_TEMP)
echo "Result: $RESULT"
exit $RESULT
