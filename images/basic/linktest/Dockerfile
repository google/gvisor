FROM ubuntu:bionic

WORKDIR /root
COPY . .

RUN apt-get update && apt-get install -y gcc
RUN gcc -O2 -o link_test link_test.c
