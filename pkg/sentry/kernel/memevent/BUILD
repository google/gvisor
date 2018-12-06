load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

package(licenses = ["notice"])  # Apache 2.0

go_library(
    name = "memevent",
    srcs = ["memory_events.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/memevent",
    visibility = ["//:sandbox"],
    deps = [
        ":memory_events_go_proto",
        "//pkg/eventchannel",
        "//pkg/log",
        "//pkg/metric",
        "//pkg/sentry/kernel",
        "//pkg/sentry/usage",
    ],
)

proto_library(
    name = "memory_events_proto",
    srcs = ["memory_events.proto"],
    visibility = ["//visibility:public"],
)

go_proto_library(
    name = "memory_events_go_proto",
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/memevent/memory_events_go_proto",
    proto = ":memory_events_proto",
    visibility = ["//visibility:public"],
)
