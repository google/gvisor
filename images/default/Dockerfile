FROM fedora:31

# Install bazel.
RUN dnf install -y dnf-plugins-core && dnf copr enable -y vbatts/bazel
RUN dnf install -y git gcc make golang gcc-c++ glibc-devel python3 which python3-pip python3-devel libffi-devel openssl-devel pkg-config glibc-static libstdc++-static patch diffutils
RUN pip install --no-cache-dir pycparser
RUN dnf install -y bazel3

# Install gcloud. Note that while this is "x86_64", it doesn't actually matter.
RUN curl https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-289.0.0-linux-x86_64.tar.gz | \
    tar zxf - google-cloud-sdk && \
    google-cloud-sdk/install.sh --quiet && \
    ln -s /google-cloud-sdk/bin/gcloud /usr/bin/gcloud

# Install Docker client for the website build.
RUN dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
RUN dnf install -y docker-ce-cli

WORKDIR /workspace
ENTRYPOINT ["/usr/bin/bazel"]
