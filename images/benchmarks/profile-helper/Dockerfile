FROM golang:1.25 AS builder

COPY main.go /main.go
RUN CGO_ENABLED=0 go build -o /profilehelper /main.go

FROM ubuntu:22.04

COPY --from=builder /profilehelper /usr/bin/
