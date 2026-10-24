# Build the merged host-network entitlement fix until it is included in dind.
# https://github.com/docker/compose/commit/1e1c577ea
ARG COMPOSE_REVISION=1e1c577eab08ceb5ff0fcf4d8e3cbbc08a34ef35

FROM golang:1.27.3-trixie@sha256:1896654cfc5c2b5ad74c07f29cb36f5d2d1cbed42e3054070fbfe444e521e83c AS compose
ARG COMPOSE_REVISION
WORKDIR /src
RUN curl -fsSL "https://codeload.github.com/docker/compose/tar.gz/${COMPOSE_REVISION}" -o /compose.tar.gz && \
    echo 'c7ba4001a9b927b78ef8a527ce3989428cd35a852d8fd7d679e9e460d1c54d8f  /compose.tar.gz' | sha256sum -c - && \
    tar -xzf /compose.tar.gz --strip-components=1 && \
    rm /compose.tar.gz && \
    CGO_ENABLED=0 make build VERSION="${COMPOSE_REVISION}" DESTDIR=/out && \
    go version -m /out/docker-compose

FROM docker:29-dind@sha256:3e5756e2b6dad6a5f1f5deacf0a19f9eaa2581b76ae092b2d4a118162e1d4d4e
ARG COMPOSE_REVISION
ENV DOCKER_COMPOSE_VERSION=${COMPOSE_REVISION}
COPY --from=compose /out/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose

RUN apk add --no-cache bash iproute2 iptables && \
    docker compose version && \
    docker buildx version

COPY start-dockerd.sh /start-dockerd.sh
ENTRYPOINT ["/start-dockerd.sh"]
