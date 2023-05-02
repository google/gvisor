FROM ubuntu:20.04 as build
RUN apt-get update && apt-get install -y git build-essential libssl-dev libz-dev
RUN git clone https://github.com/giltene/wrk2.git /tmp/wrk2 && cd /tmp/wrk2 && make

FROM ubuntu:20.04
RUN set -x \
        && apt-get update \
        && apt-get install -y \
           wget \
        && rm -rf /var/lib/apt/lists/*
COPY --from=build /tmp/wrk2/wrk /bin/wrk2
