FROM nvcr.io/nvidia/tritonserver:24.06-py3

RUN git clone --depth 1 https://github.com/triton-inference-server/server && \
    mkdir -p model_repository && \
    cp -r server/docs/examples/model_repository/* model_repository && \
    server/docs/examples/fetch_models.sh

RUN pip install tritonclient