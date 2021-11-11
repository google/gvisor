FROM ubuntu:bionic

WORKDIR /root
COPY . .
RUN chmod +x *.sh

RUN apt-get update && apt-get install -y gcc iputils-ping iproute2

# Compilation Steps.
RUN gcc -O2 -o test_copy_up test_copy_up.c
RUN gcc -O2 -o test_rewinddir test_rewinddir.c
RUN gcc -O2 -o link_test link_test.c
RUN gcc -O2 -o test_sticky test_sticky.c
RUN gcc -O2 -o host_fd host_fd.c