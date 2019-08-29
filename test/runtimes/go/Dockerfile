FROM ubuntu:bionic
ENV LANG_VER=1.12.5
ENV LANG_NAME=Go

RUN apt-get update && apt-get install -y \
  curl \
  gcc \
  git

WORKDIR /root

# Download Go 1.4 to use as a bootstrap for building Go from the source.
RUN curl -o go1.4.linux-amd64.tar.gz https://dl.google.com/go/go1.4.linux-amd64.tar.gz
RUN curl -LJO https://github.com/golang/go/archive/go${LANG_VER}.tar.gz
RUN mkdir bootstr
RUN tar -C bootstr -xzf go1.4.linux-amd64.tar.gz
RUN tar -xzf go-go${LANG_VER}.tar.gz
RUN mv go-go${LANG_VER} go

ENV GOROOT=/root/go
ENV GOROOT_BOOTSTRAP=/root/bootstr/go
ENV LANG_DIR=${GOROOT}

WORKDIR ${LANG_DIR}/src
RUN ./make.bash
# Pre-compile the tests for faster execution
RUN ["/root/go/bin/go", "tool", "dist", "test", "-compile-only"]

WORKDIR ${LANG_DIR}

COPY common /root/go/src/gvisor.dev/gvisor/test/runtimes/common/common
COPY go/proctor-go.go ${LANG_DIR}
RUN ["/root/go/bin/go", "build", "-o", "/root/go/bin/proctor", "proctor-go.go"]

ENTRYPOINT ["/root/go/bin/proctor"]
