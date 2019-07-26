FROM ubuntu:bionic
ENV LANG_VER=3.7.3
ENV LANG_NAME=Python

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

WORKDIR /root
RUN curl -o go.tar.gz https://dl.google.com/go/go1.12.6.linux-amd64.tar.gz
RUN tar -zxf go.tar.gz

# Use flags -LJO to follow the html redirect and download .tar.gz.
RUN curl -LJO https://github.com/python/cpython/archive/v${LANG_VER}.tar.gz
RUN tar -zxf cpython-${LANG_VER}.tar.gz
ENV LANG_DIR=/root/cpython-${LANG_VER}

WORKDIR ${LANG_DIR}
RUN ./configure --with-pydebug
RUN make -s -j2

COPY proctor-python.go ${LANG_DIR}

ENTRYPOINT ["/root/go/bin/go", "run", "proctor-python.go"]
