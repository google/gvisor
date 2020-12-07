FROM ubuntu:bionic

WORKDIR /root
COPY ping6.sh .
RUN chmod +x ping6.sh

RUN apt-get update && apt-get install -y iputils-ping iproute2
