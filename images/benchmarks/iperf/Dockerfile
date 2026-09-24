FROM ubuntu:jammy

RUN set -x \
        && apt-get update \
        && apt-get install -y --no-install-recommends \
            iperf ca-certificates \
        && rm -rf /var/lib/apt/lists/*

