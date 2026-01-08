ARG BASE_IMAGE=ubuntu:22.04
FROM $BASE_IMAGE

ENV DEBIAN_FRONTEND="noninteractive"

#-------------------------------------------------------------------------------
# Note: If you want to use bazel directly you will need these packages or their
#       equivalents for your distribution:
#-------------------------------------------------------------------------------
RUN apt-get update && apt-get install -y curl gnupg2 git \
        python-is-python3 python3 python3-setuptools python3-pip \
        build-essential crossbuild-essential-arm64 qemu-user-static \
        openjdk-11-jdk-headless zip unzip \
        apt-transport-https ca-certificates gnupg-agent \
        software-properties-common \
        pkg-config libffi-dev patch diffutils libssl-dev iptables kmod \
        clang crossbuild-essential-amd64 erofs-utils busybox-static libbpf-dev \
        iproute2 netcat-openbsd libnuma-dev

# This package is needed to build eBPF on amd64, but not on arm64 where it
# doesn't exist.
RUN test "$(uname -m)" != x86_64 && exit 0 || apt-get install -y libc6-dev-i386
#-------------------------------------------------------------------------------
# The rest of the file is unnecessary for building `runsc`, but are necessary
# for test targets.
#-------------------------------------------------------------------------------

# Install Docker client for the website build.
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
RUN add-apt-repository \
   "deb https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
RUN apt-get -y install docker-ce-cli

# Install gcloud.
RUN ARCH="$(uname -m | sed s/aarch64/arm/)" && \
    curl -fsSL https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-535.0.0-linux-${ARCH}.tar.gz | \
    tar zxf - google-cloud-sdk && \
    google-cloud-sdk/install.sh --quiet && \
    ln -s /google-cloud-sdk/bin/gcloud /usr/bin/gcloud

# Download the official bazel binary. The APT repository isn't used because there is not packages for arm64.
COPY bazelversion .
RUN ARCH="$(uname -m | sed s/aarch64/arm64/)" BAZEL_VERSION="$(cat ./bazelversion)" && \
    curl -fsSL https://releases.bazel.build/${BAZEL_VERSION}/release/bazel-${BAZEL_VERSION}-linux-${ARCH} -o /usr/local/bin/bazel && \
    chmod ugo+x /usr/local/bin/bazel
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/bazel"]
