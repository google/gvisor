FROM ubuntu:bionic

RUN apt-get update && apt-get install -y curl gnupg2 git python python3 python3-distutils python3-pip
RUN echo "deb [arch=amd64] http://storage.googleapis.com/bazel-apt stable jdk1.8" | tee /etc/apt/sources.list.d/bazel.list && \
    curl https://bazel.build/bazel-release.pub.gpg | apt-key add -
RUN apt-get update && apt-get install -y bazel && apt-get clean

WORKDIR /gvisor
