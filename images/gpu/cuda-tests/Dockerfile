FROM nvidia/cuda:12.2.0-devel-ubuntu20.04

WORKDIR /
COPY cuda_malloc_managed.cu .
COPY cuda_test_util.h .
COPY run.sh .
ENTRYPOINT ["/run.sh"]
