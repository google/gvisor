FROM fedora:31

RUN  dnf install -y dnf-plugins-core && dnf copr enable -y vbatts/bazel

RUN dnf install -y bazel2 git gcc make golang gcc-c++ glibc-devel python3 which python3-pip python3-devel libffi-devel openssl-devel pkg-config glibc-static libstdc++-static patch

RUN pip install pycparser

WORKDIR /gvisor
