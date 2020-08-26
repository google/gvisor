FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get install -y build-essential git pkg-config fuse3 libfuse3-3 libfuse3-dev strace

WORKDIR /fus

RUN mkdir -pv mountpoint
RUN git clone https://github.com/libfuse/libfuse

RUN gcc -Wall ./libfuse/example/passthrough.c `pkg-config fuse3 --cflags --libs` -o server-bin

CMD ["bash"]
