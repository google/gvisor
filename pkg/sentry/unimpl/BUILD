load("//tools:defs.bzl", "go_library", "go_test", "proto_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

proto_library(
    name = "unimplemented_syscall",
    srcs = ["unimplemented_syscall.proto"],
    visibility = ["//visibility:public"],
    deps = ["//pkg/sentry/arch:registers_proto"],
)

go_library(
    name = "unimpl",
    srcs = ["events.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/context",
        "//pkg/log",
    ],
)

go_test(
    name = "events_test",
    srcs = ["events_test.go"],
    deps = [
        ":unimpl",
        "//pkg/sentry/kernel",
    ],
)
