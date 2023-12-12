# https://hub.docker.com/r/ollama/ollama
FROM ollama/ollama:0.1.13

ENV PATH=$PATH:/usr/local/nvidia/bin:/bin/nvidia/bin

# Pre-install a few models.
# Although these are the smallest possible model size (7B parameters),
# these are still quite large and it would take too long for tests to
# download them on every run.
RUN bash -c '                                  \
    ( ollama serve ) & serverpid="$!";         \
    sleep 5;                                   \
    ollama pull codellama:7b &&                \
    ollama pull llama2-chinese:7b-chat &&      \
    kill "$serverpid" &&                       \
    wait "$serverpid"                          \
'
