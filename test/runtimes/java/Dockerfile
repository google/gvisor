FROM ubuntu:bionic
# This hash is associated with a specific JDK release and needed for ensuring
# the same version is downloaded every time.
ENV LANG_HASH=76072a077ee1
ENV LANG_VER=11
ENV LANG_NAME=Java

RUN apt-get update && apt-get install -y \
  autoconf \
  build-essential \
  curl \
  make \
  openjdk-${LANG_VER}-jdk \
  unzip \
  zip

WORKDIR /root
RUN curl -o go.tar.gz https://dl.google.com/go/go1.12.6.linux-amd64.tar.gz
RUN tar -zxf go.tar.gz

# Download the JDK test library.
RUN set -ex \
 && curl -fsSL --retry 10 -o /tmp/jdktests.tar.gz http://hg.openjdk.java.net/jdk/jdk${LANG_VER}/archive/${LANG_HASH}.tar.gz/test \
 && tar -xzf /tmp/jdktests.tar.gz -C /root \
 && rm -f /tmp/jdktests.tar.gz

RUN curl -o jtreg.tar.gz https://ci.adoptopenjdk.net/view/Dependencies/job/jtreg/lastSuccessfulBuild/artifact/jtreg-4.2.0-tip.tar.gz
RUN tar -xzf jtreg.tar.gz

ENV LANG_DIR=/root

COPY common /root/go/src/gvisor.dev/gvisor/test/runtimes/common/common
COPY java/proctor-java.go ${LANG_DIR}

ENTRYPOINT ["/root/go/bin/go", "run", "proctor-java.go"]
