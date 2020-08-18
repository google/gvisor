FROM ubuntu:bionic

WORKDIR /root
COPY . .

RUN apt-get update && apt-get install -y gcc
RUN gcc -O2 -o test_copy_up test_copy_up.c
RUN gcc -O2 -o test_rewinddir test_rewinddir.c
