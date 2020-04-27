FROM fedora:31
RUN dnf install -y dnf-plugins-core && dnf copr enable -y vbatts/bazel
RUN dnf install -y git gcc make golang gcc-c++ glibc-devel python3 which python3-pip python3-devel libffi-devel openssl-devel pkg-config glibc-static libstdc++-static patch
RUN pip install pycparser
RUN dnf install -y bazel3
RUN curl https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-289.0.0-linux-x86_64.tar.gz | \
    tar zxvf - google-cloud-sdk && \
    google-cloud-sdk/install.sh && \
    ln -s /google-cloud-sdk/bin/gcloud /usr/bin/gcloud
WORKDIR /workspace
ENTRYPOINT ["/usr/bin/bazel"]
