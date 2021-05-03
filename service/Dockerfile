
# UML FS (copied into /uml in service container)
# ------------------------------------------------------------------------------
FROM ubuntu:20.04 AS uml

RUN touch /flag && chmod 644 /flag && echo "OOO{M4573R_0F_PUPP375}" > /flag

RUN apt-get update -qq
RUN apt-get -qq install net-tools iproute2 openvpn netcat socat python3 python3-pip

COPY never_gonna_give_you_up.mp3 /nooopster/
COPY gen_dummy_songs.sh /nooopster/shared/
RUN cd /nooopster/shared \
 && ./gen_dummy_songs.sh \
 && rm gen_dummy_songs.sh ../never_gonna_give_you_up.mp3

RUN adduser --system openvpn && addgroup --system openvpn

COPY init.sh /init.sh
COPY supervisord.conf /supervisord.conf
# COPY resolv.conf /etc/resolv.conf
COPY public/openvpn.shared.key /
COPY slirp.sh /
COPY hosts /etc/hosts
RUN mkdir -p /var/lib/openvpn/chroot \
 && chmod 755 /var/lib/openvpn/chroot \
 && mkdir -p /var/lib/openvpn/chroot/tmp \
 && chown openvpn:openvpn /var/lib/openvpn/chroot/tmp \
 && chmod 770 /var/lib/openvpn/chroot/tmp

COPY bin/schitzo /schitzo
COPY bin/nooopster /nooopster/nooopster
COPY bin/nooopster /nooopster/shared/nooopster
COPY bin/linux /linux
COPY bin/metaserver /opennap/sbin/metaserver
COPY bin/opennap /opennap/sbin/opennap
RUN mkdir -p /opennap/share/opennap \
 && touch /opennap/share/opennap/bans \
 && touch /opennap/share/opennap/pid \
 && echo ":version 1" > /opennap/share/opennap/users \
 && echo ":version 1" > /opennap/share/opennap/channels \
 && echo "192.168.5.1:8888" > /opennap/share/opennap/metaserver.conf

ADD https://github.com/krallin/tini/releases/download/v0.19.0/tini-static /tini
RUN chmod +x /tini

# Current version in Ubuntu appears broken? Grab SLiRP from Jessie sec
ADD http://security.debian.org/debian-security/pool/updates/main/s/slirp/slirp_1.0.17-7+deb8u2_amd64.deb /slirp.deb
RUN dpkg -i slirp.deb; rm /slirp.deb

RUN python3 -m pip install supervisor

# Service container
# ------------------------------------------------------------------------------
FROM ubuntu:20.04

RUN apt-get update
RUN apt-get -y install wget xinetd socat

ENV UML_ROOT /uml
RUN adduser --system uml
COPY --from=uml / ${UML_ROOT}
RUN chown -R uml ${UML_ROOT}

COPY bin/schitzo /schitzo
COPY xinetd.conf /
COPY service_wrapper1.sh /
COPY service_wrapper2.sh /
COPY service_wrapper3.sh /
COPY get_port_number.sh /

COPY --from=uml /tini /tini
ENTRYPOINT ["/tini", "-p", "SIGTERM", "-g", "--"]

ADD http://security.debian.org/debian-security/pool/updates/main/s/slirp/slirp_1.0.17-7+deb8u2_amd64.deb /slirp.deb
RUN dpkg -i slirp.deb; rm /slirp.deb

EXPOSE 1999
CMD ["/usr/sbin/xinetd", "-syslog", "local0", "-dontfork", "-f", "/xinetd.conf"]
