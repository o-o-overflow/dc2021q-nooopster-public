#!/bin/bash -ex
cd "$(dirname "$(realpath "$0")")";

OUTPUT_DIR=../bin
mkdir -p $OUTPUT_DIR

BUILD_IMAGE_NAME=dc2021q-nooopster-src-build
docker build -t $BUILD_IMAGE_NAME .
CONTAINER_ID=$(docker create $BUILD_IMAGE_NAME)

docker cp $CONTAINER_ID:/linux/linux $OUTPUT_DIR/linux
docker cp $CONTAINER_ID:/client/nooopster $OUTPUT_DIR/nooopster
docker cp $CONTAINER_ID:/opennap/opennap $OUTPUT_DIR/opennap
docker cp $CONTAINER_ID:/opennap/metaserver $OUTPUT_DIR/metaserver
docker cp $CONTAINER_ID:/schitzo/schitzo $OUTPUT_DIR/schitzo

docker rm $CONTAINER_ID
