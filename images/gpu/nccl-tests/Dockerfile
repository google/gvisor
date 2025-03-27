FROM nvidia/cuda:12.5.0-devel-ubuntu22.04

RUN apt-get update && apt-get install git -y

RUN git clone --depth=1 https://github.com/NVIDIA/nccl-tests.git && \
    cd nccl-tests && make
