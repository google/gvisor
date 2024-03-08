# https://hub.docker.com/r/ollama/ollama
FROM ollama/ollama:0.1.26

ENV PATH=$PATH:/usr/local/nvidia/bin:/bin/nvidia/bin
ENV OLLAMA_ORIGINS=*
ENV OLLAMA_HOST=0.0.0.0:11434

# Pre-install a single model.
RUN bash -c '                                  \
    ( ollama serve ) & serverpid="$!";         \
    sleep 5;                                   \
    ollama pull mixtral:instruct &&            \
    kill "$serverpid" &&                       \
    wait "$serverpid"                          \
'
