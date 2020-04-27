FROM ubuntu:18.04

RUN set -x \
        && apt-get update \
        && apt-get install -y \
            wget \
            git \
            pkg-config \
            zip \
            g++ \
            zlib1g-dev \
            unzip \
            python3 \
        && rm -rf /var/lib/apt/lists/*
RUN wget https://github.com/bazelbuild/bazel/releases/download/0.27.0/bazel-0.27.0-installer-linux-x86_64.sh
RUN chmod +x bazel-0.27.0-installer-linux-x86_64.sh
RUN ./bazel-0.27.0-installer-linux-x86_64.sh

RUN git clone https://github.com/abseil/abseil-cpp.git
WORKDIR abseil-cpp
RUN git checkout 43ef2148c0936ebf7cb4be6b19927a9d9d145b8f
RUN bazel clean
ENV path "absl/base/..."
CMD bazel build ${path} 2>&1
