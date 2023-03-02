FROM ubuntu:18.04

RUN set -x \
        && apt-get update \
        && apt-get install -y \
            gcc \
        && rm -rf /var/lib/apt/lists/*

COPY ./syscallbench.c /
RUN gcc /syscallbench.c -o /usr/bin/syscallbench
