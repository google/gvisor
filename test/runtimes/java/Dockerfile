FROM ubuntu:bionic
# This hash is associated with a specific JDK release and needed for ensuring
# the same version is downloaded every time.
ENV LANG_HASH=af47e0398606
ENV LANG_VER=11u-dev
ENV LANG_NAME=Java

RUN apt-get update && apt-get install -y \
  autoconf \
  build-essential \
  curl\
  file \
  libasound2-dev \
  libcups2-dev \
  libfontconfig1-dev \
  libx11-dev \
  libxext-dev \
  libxrandr-dev \
  libxrender-dev \
  libxt-dev \
  libxtst-dev \
  make \
  unzip \
  zip

WORKDIR /root
RUN curl -o go.tar.gz https://dl.google.com/go/go1.12.6.linux-amd64.tar.gz
RUN tar -zxf go.tar.gz

# Use curl instead of ADD to prevent redownload every time.
RUN curl -o jdk.tar.gz http://hg.openjdk.java.net/jdk-updates/jdk${LANG_VER}/archive/${LANG_HASH}.tar.gz
# Download Java version N-1 to be used as the Boot JDK to build Java version N.
RUN curl -o bootjdk.tar.gz https://download.java.net/openjdk/jdk10/ri/openjdk-10+44_linux-x64_bin_ri.tar.gz

RUN tar -zxf jdk.tar.gz
RUN tar -zxf bootjdk.tar.gz

# Specify the JDK to be used by jtreg.
ENV JT_JAVA=/root/jdk${LANG_VER}-${LANG_HASH}/build/linux-x86_64-normal-server-release/jdk
ENV LANG_DIR=/root/jdk${LANG_VER}-${LANG_HASH}

WORKDIR ${LANG_DIR}

RUN curl -o jtreg.tar.gz https://ci.adoptopenjdk.net/view/Dependencies/job/jtreg/lastSuccessfulBuild/artifact/jtreg-4.2.0-tip.tar.gz
RUN tar -xzf jtreg.tar.gz
RUN bash configure --with-boot-jdk=/root/jdk-10 --with-jtreg=${LANG_DIR}/jtreg
RUN make clean
RUN make images

COPY proctor-java.go ${LANG_DIR}

ENTRYPOINT ["/root/go/bin/go", "run", "proctor-java.go"]
