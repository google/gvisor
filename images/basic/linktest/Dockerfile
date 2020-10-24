FROM ubuntu:bionic

WORKDIR /root
COPY . .

RUN apt-get update && apt-get --no-install-recommends install -y apt-utils ca-certificates gcc
RUN gcc -O2 -o link_test link_test.c
