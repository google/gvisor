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

# Download the JDK source which contains the tests.
# Proctor expects this to be in /root/jdk.
WORKDIR /root
RUN set -ex \
 && curl -fsSL --retry 10 -o /tmp/jdk.tar.gz https://github.com/openjdk/jdk17u/archive/refs/tags/jdk-17.0.2-ga.tar.gz \
 && tar -zxzf /tmp/jdk.tar.gz \
 && mv jdk17u-jdk-17.0.2-ga /root/jdk \
 && rm -f /tmp/jdk.tar.gz

# Install jtreg and add to PATH.
#
# NOTE: None of the tagged releases (up to jtreg-6.2+1) build correctly, so we
# use a recent commit that does work.
#
# ALSO NOTE: The installed location of the JDK is annoyingly path dependant,
# and is "/usr/lib/jvm/java-17-openjdk-amd64" on x86_64 but "-aarch64" on
# ARM64. The `build.sh` step below uses a wildcard to work around the fact that
# we don't know the full path.
ARG COMMIT=284b16ed44b3bc25e9dde11efc4b1013702871cb
RUN set -ex \
 && curl -fsSL --retry 10 -o jtreg.tar.gz https://github.com/openjdk/jtreg/archive/${COMMIT}.tar.gz \
 && tar -zxvf jtreg.tar.gz \
 && mv jtreg-${COMMIT} jtreg \
 && bash jtreg/make/build.sh --jdk /usr/lib/jvm/java-17-openjdk-* \
 && rm -f jtreg.tar.gz

ENV PATH="/root/jtreg/build/images/jtreg/bin:$PATH"
