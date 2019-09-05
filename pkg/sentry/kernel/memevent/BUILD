load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")
load("//tools/build_defs/proto/cpp:cc_proto_library.bzl", "cc_proto_library")

package(licenses = ["notice"])

go_library(
    name = "memevent",
    srcs = ["memory_events.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/kernel/memevent",
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

cc_proto_library(
    name = "memory_events_cc_proto",
    proto = ":memory_events_proto",
    visibility = ["//visibility:public"],
)

go_proto_library(
    name = "memory_events_go_proto",
    importpath = "gvisor.dev/gvisor/pkg/sentry/kernel/memevent/memory_events_go_proto",
    proto = ":memory_events_proto",
    visibility = ["//visibility:public"],
)
