load("//tools:defs.bzl", "go_library", "proto_library")

package(licenses = ["notice"])

go_library(
    name = "memevent",
    srcs = ["memory_events.go"],
    visibility = ["//:sandbox"],
    deps = [
        ":memory_events_go_proto",
        "//pkg/eventchannel",
        "//pkg/log",
        "//pkg/metric",
        "//pkg/sentry/kernel",
        "//pkg/sentry/usage",
        "//pkg/sync",
    ],
)

proto_library(
    name = "memory_events",
    srcs = ["memory_events.proto"],
    visibility = ["//visibility:public"],
)
