FROM ubuntu:bionic
RUN apt-get update && apt-get install -y \
  autoconf \
  build-essential \
  curl \
  make \
  openjdk-11-jdk \
  unzip \
  zip

# Download the JDK test library.
WORKDIR /root
RUN set -ex \
 && curl -fsSL --retry 10 -o /tmp/jdktests.tar.gz http://hg.openjdk.java.net/jdk-updates/jdk11u/archive/8b3498547395.tar.gz/test \
 && tar -xzf /tmp/jdktests.tar.gz \
 && mv jdk11u-8b3498547395/test test \
 && rm -f /tmp/jdktests.tar.gz

# Install jtreg and add to PATH.
RUN curl -o jtreg.tar.gz https://ci.adoptopenjdk.net/view/Dependencies/job/jtreg/lastSuccessfulBuild/artifact/jtreg-4.2.0-tip.tar.gz
RUN tar -xzf jtreg.tar.gz
ENV PATH="/root/jtreg/bin:$PATH"
