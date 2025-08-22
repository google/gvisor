FROM nvidia/cuda:12.8.1-devel-ubuntu24.04

RUN apt-get update && apt-get install git -y

RUN git clone --depth=1 https://github.com/NVIDIA/nccl-tests.git && \
    cd nccl-tests && make
