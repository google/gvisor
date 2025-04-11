# https://hub.docker.com/r/ollama/ollama
FROM ollama/ollama:0.5.1

ENV PATH=$PATH:/usr/local/nvidia/bin
ENV OLLAMA_ORIGINS=*
ENV OLLAMA_HOST=0.0.0.0:11434

# Pre-install a few models.
# Although these are the smallest possible model size (7B parameters),
# these are still quite large and it would take too long for tests to
# download them on every run.
RUN bash -c '                                  \
    ( ollama serve ) & serverpid="$!";         \
    sleep 5;                                   \
    ollama pull codellama:7b-instruct  &&      \
    ollama pull llama2-chinese:7b-chat &&      \
    ollama pull llava:7b-v1.6          &&      \
    kill "$serverpid" &&                       \
    wait "$serverpid"                          \
'
