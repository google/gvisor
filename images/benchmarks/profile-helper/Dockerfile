FROM ubuntu:22.04

COPY main.go /main.go
RUN apt-get update && apt-get install -y golang-go && \
  go build -o /usr/bin/profilehelper /main.go && \
  rm -f /main.go
