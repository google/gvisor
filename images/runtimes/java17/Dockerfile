FROM ubuntu:bionic
RUN apt-get update && apt-get install -y \
  autoconf \
  build-essential \
  ca-certificates-java \
  curl \
  java-common \
  make \
  openjdk-17-jdk \
  unzip \
  zip

# Download the JDK test library.
WORKDIR /root
RUN set -ex \
 && curl -fsSL --retry 10 -o /tmp/jdktests.tar.gz https://github.com/openjdk/jdk17u/archive/refs/tags/jdk-17.0.3+4.tar.gz \
 && tar -xzf /tmp/jdktests.tar.gz \
 && ln -s jdk17u-jdk-17.0.3-4/test test \
 && rm -f /tmp/jdktests.tar.gz

# Install jtreg and add to PATH.
# FIXME: All the currently tagged jtreg releases (up to jtreg-6.2+1) give
# compilation errors when building. Once a good release exists, we should use
# that rather than fetching from head.
RUN set -ex \
 && curl -fsSL --retry 10 -o jtreg.zip https://github.com/openjdk/jtreg/archive/refs/heads/master.zip \
 && unzip jtreg.zip \
 && bash jtreg-master/make/build.sh --jdk /usr/lib/jvm/java-17-openjdk-amd64 \
 && rm -f jtreg.zip

ENV PATH="/root/jtreg-master/build/images/jtreg/bin:$PATH"
