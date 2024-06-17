FROM us-docker.pkg.dev/vertex-ai/vertex-vision-model-garden-dockers/pytorch-vllm-serve:20240313_0916_RC00

RUN mkdir -p /model && chmod 000 /model
COPY /run.sh /
RUN chmod 555 /run.sh
VOLUME /model
EXPOSE 7080
CMD /run.sh
