FROM ubuntu:18.04

RUN set -x \
        && apt-get update \
        && apt-get --no-install-recommends install -y apt-utils ca-certificates \
            fio \
        && rm -rf /var/lib/apt/lists/*
