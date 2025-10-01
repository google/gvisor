FROM ubuntu:bionic

WORKDIR /root
COPY . .
RUN chmod +x *.sh

RUN apt-get update && apt-get install -y \
    build-essential iputils-ping iproute2 iptables

# Compilation Steps.
RUN gcc -O2 -o test_copy_up test_copy_up.c
RUN gcc -O2 -o test_rewinddir test_rewinddir.c
RUN gcc -O2 -o link_test link_test.c
RUN gcc -O2 -o test_sticky test_sticky.c
RUN gcc -O2 -o host_fd host_fd.c
RUN gcc -O2 -o host_connect host_connect.c
RUN gcc -O2 -o tcp_server tcp_server.c
RUN gcc -O2 -o tcp_stress_server tcp_stress_server.c -pthread
RUN gcc -O2 -o tcp_loopback tcp_loopback.c

# Add nonprivileged regular user named "nonroot".
RUN groupadd --gid 1337 nonroot && \
    useradd --uid 1338 --gid 1337 \
        --create-home \
        --shell $(which bash) \
        --password '' \
        nonroot

# Copy host_connect to /home/nonroot so that "nonroot" can execute it.
RUN cp host_connect /home/nonroot/host_connect
