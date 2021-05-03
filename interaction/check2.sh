#!/bin/bash -e
# Parallelized test of the server/client

START=$RANDOM
NUM_JOBS=250
NUM_PARALLEL=50
JOBSFILE=$(mktemp)

echo "" > $JOBSFILE
for uid in $(seq $START `expr $START + $NUM_JOBS - 1`);
do
	uname="user$uid"
	cmd="./check1.py --user=$uname $1 $2 >/dev/null"
	echo $cmd >> $JOBSFILE
done

parallel -j $NUM_PARALLEL --halt now,fail=1 < $JOBSFILE
