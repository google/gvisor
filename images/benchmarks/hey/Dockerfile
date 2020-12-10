FROM golang:1.15 as build
RUN go get github.com/rakyll/hey
WORKDIR /go/src/github.com/rakyll/hey
RUN go mod download
RUN CGO_ENABLED=0 go build -o /hey hey.go

FROM ubuntu:18.04
RUN set -x \
        && apt-get update \
        && apt-get install -y \
           wget \
        && rm -rf /var/lib/apt/lists/*
COPY --from=build /hey /bin/hey
