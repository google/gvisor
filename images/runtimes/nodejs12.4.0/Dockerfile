FROM ubuntu:bionic
RUN apt-get update && apt-get install -y \
  curl \
  dumb-init \
  g++ \
  make \
  python

WORKDIR /root
ARG VERSION=v12.4.0
RUN curl -o node-${VERSION}.tar.gz https://nodejs.org/dist/${VERSION}/node-${VERSION}.tar.gz
RUN tar -zxf node-${VERSION}.tar.gz

WORKDIR /root/node-${VERSION}
RUN ./configure
RUN make
RUN make test-build

# Including dumb-init emulates the Linux "init" process, preventing the failure
# of tests involving worker processes.
ENTRYPOINT ["/usr/bin/dumb-init"]
