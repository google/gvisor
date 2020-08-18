FROM ubuntu:18.04

RUN set -x \
        && apt-get update \
        && apt-get install -y \
           wget \
        && rm -rf /var/lib/apt/lists/*

RUN wget https://storage.googleapis.com/hey-release/hey_linux_amd64 \
        && chmod 777 hey_linux_amd64 \
        && cp hey_linux_amd64 /bin/hey \
        && rm hey_linux_amd64
