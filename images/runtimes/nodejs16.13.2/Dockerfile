FROM ubuntu:bionic
RUN apt-get update && apt-get install -y \
  curl \
  dumb-init \
  g++ \
  make \
  python \
  python3.8

WORKDIR /root
ARG VERSION=v16.13.2
RUN curl -o node-${VERSION}.tar.gz https://nodejs.org/dist/${VERSION}/node-${VERSION}.tar.gz
RUN tar -zxf node-${VERSION}.tar.gz

WORKDIR /root/node-${VERSION}
RUN ./configure
RUN make test-build

# Including dumb-init emulates the Linux "init" process, preventing the failure
# of tests involving worker processes.
ENTRYPOINT ["/usr/bin/dumb-init"]
