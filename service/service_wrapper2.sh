#!/bin/bash
# exec 2>/dev/null
# set -e

SERVICE_PID=0

# Find a free port
PORT_RANGE_START=30000
PORT_RANGE_END=35000

# FIXME: SLiRP doesn't set SO_REUSEADDR? Give big range to avoid issues

PORT_FILE=/tmp/serv.ports
INTERNAL_SERVICE_PORT=$(./get_port_number.sh $PORT_RANGE_START $PORT_RANGE_END $PORT_FILE)
if [[ "$?" != "0" ]]; then
	echo "[!] Service allocation failure"
	exit 1
fi

export INTERNAL_SERVICE_PORT

function cleanup {
	# echo "[*] Removing ${PORT_FILE}.${INTERNAL_SERVICE_PORT}"
	if [[ "$SERVICE_PID" != "0" ]]; then
		# echo "[*] Killing service..."
		kill -9 -$(ps -o pgid= ${SERVICE_PID} | grep -o '[0-9]*')
	fi
	rm -f ${PORT_FILE}.${INTERNAL_SERVICE_PORT}
}
trap cleanup EXIT

# Launch service
# echo -n "[*] Spawning service on $INTERNAL_SERVICE_PORT..."
./service_wrapper3.sh &
SERVICE_PID=$!
# echo "pid=$SERVICE_PID"

# Connect stdin/stdout to service listening on internal service port
stdbuf -i0 -o0 -e0 \
socat - TCP:localhost:$INTERNAL_SERVICE_PORT,retry=5,interval=5,nodelay
