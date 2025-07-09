FROM nvidia/cuda:12.8.1-devel-ubuntu22.04

WORKDIR /
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
      vim \
      wget \
      x11-xserver-utils \
      xdotool \
      xvfb \
      zlib1g zlib1g-dev \
      && apt -y purge 'golang*'

RUN git clone --depth=1 --branch=v12.8 --single-branch \
      https://github.com/NVIDIA/cuda-samples.git /cuda-samples && cd /cuda-samples

ADD *.cu *.h *.sh *.go *.cc /

RUN chmod 555 /*.sh && /install_go.sh && rm /install_go.sh && \
    gcc -o /unsupported_ioctl /unsupported_ioctl.cc && \
    go install \
      github.com/TheZoraiz/ascii-image-converter@d05a757c5e02ab23e97b6f6fca4e1fbeb10ab559 && \
    mv "$HOME/go/bin/ascii-image-converter" /usr/bin/ && \
    go build -o /run_sample /run_sample.go && \
    mkdir /cuda-samples/build && cd /cuda-samples/build && \
    cmake ..

# Override entrypoint to nothing, otherwise all invocations will have
# a copyright notice printed, which breaks parsing the stdout logs.
ENTRYPOINT []