FROM ubuntu:22.04

ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update && apt-get install -y docker.io

CMD bash -xec 'mount -t tmpfs cgroups /sys/fs/cgroup && \
               mkdir /sys/fs/cgroup/devices && \
               mount -t cgroup -o devices devices /sys/fs/cgroup/devices && \
               exec /usr/bin/dockerd --bridge=none --iptables=false --ip6tables=false -D'
