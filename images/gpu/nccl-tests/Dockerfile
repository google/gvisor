# CUDA 12.8 is the first toolkit whose nvcc knows the Blackwell arches
# (sm_100/sm_120); nccl-tests derives its gencode list from the toolkit.
FROM nvidia/cuda:12.8.1-devel-ubuntu22.04

RUN apt-get update && apt-get install git -y

RUN git clone --depth=1 https://github.com/NVIDIA/nccl-tests.git && \
    cd nccl-tests && make
