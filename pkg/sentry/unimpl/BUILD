load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

package(licenses = ["notice"])

proto_library(
    name = "unimplemented_syscall_proto",
    srcs = ["unimplemented_syscall.proto"],
    visibility = ["//visibility:public"],
    deps = ["//pkg/sentry/arch:registers_proto"],
)

cc_proto_library(
    name = "unimplemented_syscall_cc_proto",
    proto = ":unimplemented_syscall_proto",
    visibility = ["//visibility:public"],
)

go_proto_library(
    name = "unimplemented_syscall_go_proto",
    importpath = "gvisor.dev/gvisor/pkg/sentry/unimpl/unimplemented_syscall_go_proto",
    proto = ":unimplemented_syscall_proto",
    visibility = ["//visibility:public"],
    deps = ["//pkg/sentry/arch:registers_go_proto"],
)

go_library(
    name = "unimpl",
    srcs = ["events.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/unimpl",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/sentry/context",
    ],
)
