FROM ubuntu:bionic

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y iptables netcat tcpdump iproute2 tshark
RUN hash -r
CMD /bin/bash
