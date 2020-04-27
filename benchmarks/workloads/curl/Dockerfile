FROM ubuntu:18.04

RUN set -x \
        && apt-get update \
        && apt-get install -y \
            curl \
        && rm -rf /var/lib/apt/lists/*

# Accept a host and port parameter.
ENV host localhost
ENV port 8080

# Spin until we make a successful request.
CMD ["sh", "-c", "while ! curl -v -i http://$host:$port; do true; done"]
