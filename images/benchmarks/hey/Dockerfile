FROM golang:1.25 AS build
RUN CGO_ENABLED=0 go install github.com/rakyll/hey@latest
RUN cp /go/bin/hey /hey

FROM ubuntu:jammy
RUN set -x \
        && apt-get update \
        && apt-get install -y --no-install-recommends \
           wget ca-certificates \
        && rm -rf /var/lib/apt/lists/*
COPY --from=build /hey /bin/hey
