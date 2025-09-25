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
RUN curl https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-535.0.0-linux-x86_64.tar.gz | \
    tar zxf - google-cloud-sdk && \
    google-cloud-sdk/install.sh --quiet && \
    ln -s /google-cloud-sdk/bin/gcloud /usr/bin/gcloud

# FIXME: rules_go is configured in MODULE.bazel to download its own Go SDK and
# it should not use other go binaries.
ENV GO_VERSION 1.25.1
ENV GO_DOWNLOAD_BASE_URL https://dl.google.com/go/
RUN ARCH="$(uname -m)" && \
    case "$ARCH" in \
        x86_64) GO_ARCH="amd64" ;; \
        aarch64) GO_ARCH="arm64" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac && \
    GO_FILENAME="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" && \
    GO_URL="${GO_DOWNLOAD_BASE_URL}${GO_FILENAME}" && \
    curl -sSL "${GO_URL}" | tar -xz -C /usr/local
ENV PATH=$PATH:/usr/local/go/bin

RUN add-apt-repository ppa:longsleep/golang-backports && apt update && apt install -y golang-go

# Download the official bazel binary. The APT repository isn't used because there is not packages for arm64.
COPY bazelversion .
RUN sh -c 'curl -o /usr/local/bin/bazel https://releases.bazel.build/$(cat ./bazelversion)/release/bazel-$(cat ./bazelversion)-linux-$(uname -m | sed s/aarch64/arm64/) && chmod ugo+x /usr/local/bin/bazel'
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/bazel"]
