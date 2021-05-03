FROM ubuntu:20.04

ENV TERM linux

RUN apt-get update -qq
RUN DEBIAN_FRONTEND="noninteractive" apt-get -qq install net-tools iproute2 openvpn netcat socat python3 python3-pip parallel systemd-sysv

COPY requirements.txt /
RUN pip3 install -r /requirements.txt

ADD https://github.com/krallin/tini/releases/download/v0.19.0/tini-static /tini
RUN chmod +x /tini

# Current version in Ubuntu appears broken? Grab SLiRP from Jessie sec
ADD http://security.debian.org/debian-security/pool/updates/main/s/slirp/slirp_1.0.17-7+deb8u2_amd64.deb /slirp.deb
RUN dpkg -i slirp.deb; rm /slirp.deb

COPY bin/linux /
COPY vpn.sh /
COPY openvpn.shared.key /
COPY init.sh /
COPY exploit1.py /
COPY exploit1_vpn.sh /
COPY check1.py /
COPY check1_vpn.sh /
# COPY check2.sh /

RUN apt-get -qq install iputils-ping