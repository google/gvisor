FROM ubuntu:bionic

WORKDIR /root
COPY . .
RUN chmod +x *.sh

RUN apt-get update && apt-get install -y gcc iputils-ping iproute2
