FROM ubuntu:20.04 as build

# Install build dependencies:
RUN apt-get update && apt-get install -y git build-essential libssl-dev libz-dev

# Clone repo at the commit ID we expect to patch:
RUN git clone https://github.com/giltene/wrk2.git /tmp/wrk2 \
 && cd /tmp/wrk2 \
 && git reset --hard 44a94c17d8e6a0bac8559b53da76848e430cb7a7

# Update LuaJIT to an ARM-compatible version:
RUN git clone https://luajit.org/git/luajit.git /tmp/luajit \
 && cd /tmp/luajit \
 && git reset --hard 224129a8e64bfa219d35cd03055bf03952f167f6 \
 && cp -ar /tmp/luajit/* /tmp/wrk2/deps/luajit/

# Patch files to make them ARM-compatible:
RUN cd /tmp/wrk2 \
 && sed -ri 's/#include <x86intrin.h>//g' src/hdr_histogram.c \
 && sed -ri 's/\bluaL_reg\b/luaL_Reg/g'   src/script.c

# Make.
RUN cd /tmp/wrk2 && make

FROM ubuntu:20.04
RUN set -x \
        && apt-get update \
        && apt-get install -y \
           wget \
        && rm -rf /var/lib/apt/lists/*
COPY --from=build /tmp/wrk2/wrk /bin/wrk2
