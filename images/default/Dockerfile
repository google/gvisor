FROM ubuntu:focal

ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update && apt-get install -y curl gnupg2 git \
        python python3 python3-distutils python3-pip \
        build-essential crossbuild-essential-arm64 qemu-user-static \
        openjdk-11-jdk-headless zip unzip \
        apt-transport-https ca-certificates gnupg-agent \
        software-properties-common \
        pkg-config libffi-dev patch diffutils libssl-dev

# Install Docker client for the website build.
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
RUN add-apt-repository \
   "deb https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
RUN apt-get install docker-ce-cli

# Install gcloud.
RUN curl https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-289.0.0-linux-x86_64.tar.gz | \
    tar zxf - google-cloud-sdk && \
    google-cloud-sdk/install.sh --quiet && \
    ln -s /google-cloud-sdk/bin/gcloud /usr/bin/gcloud

# Download the official bazel binary. The APT repository isn't used because there is not packages for arm64.
RUN sh -c 'curl -o /usr/local/bin/bazel https://releases.bazel.build/4.0.0/release/bazel-4.0.0-linux-$(uname -m | sed s/aarch64/arm64/) && chmod ugo+x /usr/local/bin/bazel'
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/bazel"]
