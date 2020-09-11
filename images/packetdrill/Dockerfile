FROM ubuntu:bionic
RUN apt-get update && apt-get install -y net-tools git iptables iputils-ping \
        netcat tcpdump jq tar bison flex make
# Pick up updated git.
RUN hash -r
RUN git clone --depth 1 --branch packetdrill-v2.0 \
        https://github.com/google/packetdrill.git
RUN cd packetdrill/gtests/net/packetdrill && ./configure && make
