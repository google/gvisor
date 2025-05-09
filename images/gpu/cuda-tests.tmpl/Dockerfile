ARG TEMPLATE_VERSION=PLEASE_USE_MAKEFILE_TO_BUILD_THIS_IMAGE

FROM nvidia/cuda:${TEMPLATE_VERSION}-devel-ubuntu22.04

# Necessary to keep TEMPLATE_VERSION available for future
# lines in this Dockerfile past the FROM.
ARG TEMPLATE_VERSION

WORKDIR /
COPY *.cu *.h *.sh *.go *.cc /
ENV PATH=$PATH:/usr/local/nvidia/bin
RUN export DEBIAN_FRONTEND=noninteractive; \
    apt-get update && \
    apt-get install -y \
      build-essential \
      cmake \
      freeglut3 freeglut3-dev \
      git \
      golang \
      imagemagick \
      libegl-dev \
      libfreeimage3 libfreeimage-dev \
      libfreeimageplus3 libfreeimageplus-dev \
      libgles2-mesa-dev \
      libglfw3 libglfw3-dev \
      libglu1-mesa libglu1-mesa-dev \
      libxi-dev \
      libxmu-dev \
      llvm \
      mpich \
      pkg-config \
      x11-xserver-utils \
      xdotool \
      xvfb \
      zlib1g zlib1g-dev \
    && \
    chmod 555 /*.sh && \
    git clone --depth=1 \
      --branch="v$(echo "${TEMPLATE_VERSION}" | cut -d. -f1-2)" \
      --single-branch \
      https://github.com/NVIDIA/cuda-samples.git /cuda-samples && \
    go install \
      github.com/TheZoraiz/ascii-image-converter@d05a757c5e02ab23e97b6f6fca4e1fbeb10ab559 && \
    mv "$HOME/go/bin/ascii-image-converter" /usr/bin/ && \
    gcc -o /unsupported_ioctl /unsupported_ioctl.cc && \
    go build -o /run_sample /run_sample.go

# Override entrypoint to nothing, otherwise all invocations will have
# a copyright notice printed, which breaks parsing the stdout logs.
ENTRYPOINT []
