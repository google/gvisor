FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y && apt-get upgrade -y
RUN apt-get update && apt-get install -y \
    git \
    meson \
    ninja-build \
    gcc \
    g++ \
    pkg-config \
    python3-pip \
    python3-jinja2 \
    python3-lxml \
    libcap-dev \
    libmount-dev \
    libseccomp-dev \
    libdw-dev \
    libudev-dev \
    libkmod-dev \
    libblkid-dev \
    gperf \
    bash-completion \
    && rm -rf /var/lib/apt/lists/*

# 2. Clone the systemd repository
WORKDIR /systemd
RUN git clone --depth 1 https://github.com/systemd/systemd.git .

# 3. Setup the build directory
# We disable some heavy optional features to speed up the test cycle
RUN meson setup build/ \
    -Dman=false \
    -Dhtml=false \
    -Dtests=true \
    -Dinstall-tests=true

# 4. Build systemd
RUN ninja -C build/