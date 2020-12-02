FROM golang:1.15 as build-agent
RUN git clone --depth=1 --branch=v3.25.0 https://github.com/buildkite/agent
RUN cd agent && go build -i -o /buildkite-agent .

FROM golang:1.15 as build-agent-metrics
RUN git clone --depth=1 --branch=v5.2.0 https://github.com/buildkite/buildkite-agent-metrics
RUN cd buildkite-agent-metrics && go build -i -o /buildkite-agent-metrics .

FROM gcr.io/distroless/base-debian10
COPY --from=build-agent /buildkite-agent /
COPY --from=build-agent-metrics /buildkite-agent-metrics /
CMD ["/buildkite-agent"]
