FROM ubuntu:bionic
ENV LANG_VER=7.3.6
ENV LANG_NAME=PHP

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
RUN curl -o go.tar.gz https://dl.google.com/go/go1.12.6.linux-amd64.tar.gz
RUN tar -zxf go.tar.gz

RUN curl -o php-${LANG_VER}.tar.gz https://www.php.net/distributions/php-${LANG_VER}.tar.gz
RUN tar -zxf php-${LANG_VER}.tar.gz
ENV LANG_DIR=/root/php-${LANG_VER}

WORKDIR ${LANG_DIR}
RUN ./configure
RUN make

COPY common /root/go/src/gvisor.dev/gvisor/test/runtimes/common/common
COPY php/proctor-php.go ${LANG_DIR}

ENTRYPOINT ["/root/go/bin/go", "run", "proctor-php.go"]
