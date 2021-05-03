FROM ubuntu:20.04

RUN apt-get update
RUN apt-get -y install build-essential flex bison xz-utils wget bc zlib1g-dev

RUN wget -O /linux.tar.xz https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.11.15.tar.xz
COPY uml.config /uml.config
COPY 0001-uml-use-urandom.patch /linux/
RUN mkdir -p /linux \
 && cd /linux \
 && tar --strip-components=1 -xf /linux.tar.xz \
 && mv /uml.config .config \
 && patch -p1 < 0001-uml-use-urandom.patch \
 && make ARCH=um -j12


COPY client /client
RUN make -C /client

COPY opennap-0.44 /opennap
RUN cd /opennap \
 && ./configure --prefix=/opennap \
 && make -j8

COPY schitzo /schitzo
RUN make -C /schitzo
