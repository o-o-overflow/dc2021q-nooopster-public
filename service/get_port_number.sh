#!/bin/bash
# A port is selected from the specified range and a temporary file will be
# created to reserve the port while the service runs. Remove this file to free
# the port for use.
#
# usage: ./get_port_number.sh <port range start> <port range end> <port lock file>
#

RANGE_START=$1
RANGE_END=$2
PORT_LOCK_FILE=$3

COUNTFILE=/tmp/port.count

(
	flock 9
	COUNT=$(if [[ -e $COUNTFILE ]]; then cat $COUNTFILE; else echo -n 0; fi)
	for I in $(seq 0 $(( $RANGE_END - $RANGE_START)))
	do
		S=$(( $COUNT + $I ))
		PORT=$(( $RANGE_START + $S % ($RANGE_END - $RANGE_START) ))
		# echo -e "COUNT=$COUNT\nI=$I\nS=$S\nPORT=$PORT"
		echo -n $S > $COUNTFILE
		if [[ ! -e ${PORT_LOCK_FILE}.${PORT} ]]
		then
			touch ${PORT_LOCK_FILE}.${PORT}
			echo -n $PORT
			exit 0
		fi
	done
	exit 1
) 9>/var/lock/port.lock
exit $?
