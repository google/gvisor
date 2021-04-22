FROM ubuntu:bionic
RUN apt-get update && apt-get install -y \
  autoconf \
  automake \
  bison \
  build-essential \
  curl \
  libtool \
  libxml2-dev \
  re2c

WORKDIR /root
ARG VERSION=7.3.6
RUN curl -o php-${VERSION}.tar.gz https://www.php.net/distributions/php-${VERSION}.tar.gz
RUN tar -zxf php-${VERSION}.tar.gz

WORKDIR /root/php-${VERSION}
RUN ./configure --enable-sockets
RUN make
