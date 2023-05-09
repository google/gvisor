FROM golang:1.15 as build-agent
RUN git clone --depth=1 --branch=v3.25.0 https://github.com/buildkite/agent
RUN cd agent && go build -i -o /buildkite-agent .

FROM gcr.io/distroless/base-debian10
COPY --from=build-agent /buildkite-agent /
CMD ["/buildkite-agent"]
