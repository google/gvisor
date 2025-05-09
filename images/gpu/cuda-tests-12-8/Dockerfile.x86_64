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
      x11-xserver-utils \
      xdotool \
      xvfb \
      zlib1g zlib1g-dev

RUN git clone --depth=1 --branch=v12.8 --single-branch \
      https://github.com/NVIDIA/cuda-samples.git /cuda-samples && cd /cuda-samples

RUN apt install -y wget && apt -y purge golang*

RUN wget https://go.dev/dl/go1.24.1.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz && \
    ln -s /usr/local/go/bin/go /usr/local/bin/go

ADD *.cu *.h *.sh *.go *.cc /

RUN chmod 555 /*.sh && gcc -o /unsupported_ioctl /unsupported_ioctl.cc && \
    go install \
      github.com/TheZoraiz/ascii-image-converter@d05a757c5e02ab23e97b6f6fca4e1fbeb10ab559 && \
    mv "$HOME/go/bin/ascii-image-converter" /usr/bin/ && \
    go build -o /run_sample /run_sample.go

RUN mkdir /cuda-samples/build && cd /cuda-samples/build && \
      cmake ..

# Override entrypoint to nothing, otherwise all invocations will have
# a copyright notice printed, which breaks parsing the stdout logs.
ENTRYPOINT []