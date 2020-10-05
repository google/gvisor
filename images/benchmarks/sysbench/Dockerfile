FROM ubuntu:18.04

RUN set -x \
        && apt-get update \
        && apt-get install -y \
            sysbench \
        && rm -rf /var/lib/apt/lists/*
