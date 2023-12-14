FROM ubuntu:22.04

ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update && apt-get install -y docker.io

CMD exec /usr/bin/dockerd --bridge=none --iptables=false --ip6tables=false -D
