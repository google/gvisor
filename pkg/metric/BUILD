package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

go_library(
    name = "metric",
    srcs = ["metric.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/metric",
    visibility = ["//:sandbox"],
    deps = [
        ":metric_go_proto",
        "//pkg/eventchannel",
        "//pkg/log",
    ],
)

proto_library(
    name = "metric_proto",
    srcs = ["metric.proto"],
    visibility = ["//:sandbox"],
)

go_proto_library(
    name = "metric_go_proto",
    importpath = "gvisor.googlesource.com/gvisor/pkg/metric/metric_go_proto",
    proto = ":metric_proto",
    visibility = ["//:sandbox"],
)

go_test(
    name = "metric_test",
    srcs = ["metric_test.go"],
    embed = [":metric"],
    deps = [
        ":metric_go_proto",
        "//pkg/eventchannel",
        "@com_github_golang_protobuf//proto:go_default_library",
    ],
)
