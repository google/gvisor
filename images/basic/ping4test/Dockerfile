FROM ubuntu:bionic

WORKDIR /root
COPY ping4.sh .
RUN chmod +x ping4.sh

RUN apt-get update && apt-get install -y iputils-ping
