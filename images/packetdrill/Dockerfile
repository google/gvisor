FROM ubuntu:jammy
RUN apt-get update && apt-get install -y net-tools git iptables iputils-ping \
        netcat tcpdump jq tar bison flex make
# Pick up updated git.
RUN hash -r
RUN git clone --depth 1 https://github.com/google/packetdrill.git
RUN cd packetdrill/gtests/net/packetdrill && ./configure && make
