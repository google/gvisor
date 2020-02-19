FROM ubuntu:bionic

RUN apt-get update
RUN apt-get install -y net-tools git iptables iputils-ping netcat tcpdump jq tar
RUN hash -r
RUN git clone --branch packetdrill-v2.0 \
        https://github.com/google/packetdrill.git
RUN cd packetdrill/gtests/net/packetdrill && ./configure && \
        apt-get install -y bison flex make && make
RUN apt-get install -y g++
RUN apt-get install -y python3
RUN apt-get install -y python3-pip
RUN pip3 install scapy
RUN apt-get install -y tcpreplay
RUN apt-get install -y libjsoncpp-dev
RUN apt-get install -y iproute2
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tshark
