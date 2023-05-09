FROM ubuntu:bionic
RUN apt-get update && apt-get install -y \
  curl \
  gcc \
  libbz2-dev \
  libffi-dev \
  liblzma-dev \
  libreadline-dev \
  libssl-dev \
  make \
  zlib1g-dev

# Use flags -LJO to follow the html redirect and download .tar.gz.
WORKDIR /root
ARG VERSION=3.10.2
RUN curl -LJO https://github.com/python/cpython/archive/v${VERSION}.tar.gz
RUN tar -zxf cpython-${VERSION}.tar.gz

WORKDIR /root/cpython-${VERSION}
RUN ./configure --with-pydebug
RUN make -s -j2
