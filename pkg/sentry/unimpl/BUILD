load("//tools:defs.bzl", "go_library", "proto_library")

package(licenses = ["notice"])

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
