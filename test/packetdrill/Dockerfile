FROM ubuntu:bionic

RUN apt-get update
RUN apt-get install -y net-tools git iptables iputils-ping netcat tcpdump jq tar
RUN hash -r
RUN git clone --branch packetdrill-v2.0 \
        https://github.com/google/packetdrill.git
RUN cd packetdrill/gtests/net/packetdrill && ./configure && \
        apt-get install -y bison flex make && make
