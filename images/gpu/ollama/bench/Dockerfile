# https://hub.docker.com/r/ollama/ollama
FROM ollama/ollama:0.1.26

ENV PATH=$PATH:/usr/local/nvidia/bin:/bin/nvidia/bin
ENV OLLAMA_ORIGINS=*
ENV OLLAMA_HOST=0.0.0.0:11434

COPY pull.sh /tmp

# Pre-install models useful for benchmarking.
# These are huge (total ~120 GiB), but necessary to benchmark
# models of various sizes. They are in their own image file to
# keep the test-only image lighter by comparison.
RUN /tmp/pull.sh codellama:7b-instruct
RUN /tmp/pull.sh codellama:34b-instruct
RUN /tmp/pull.sh llama2-chinese:7b-chat
RUN /tmp/pull.sh llama2:13b-chat
RUN /tmp/pull.sh llama2:70b-chat
RUN /tmp/pull.sh mistral:7b-instruct
RUN /tmp/pull.sh mixtral:instruct
RUN /tmp/pull.sh gemma:2b-instruct
RUN /tmp/pull.sh gemma:7b-instruct
RUN /tmp/pull.sh llava:7b-v1.6
RUN /tmp/pull.sh llava:34b-v1.6
