package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")
load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "syscalls",
    srcs = [
        "epoll.go",
        "polling.go",
        "syscalls.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/syscalls",
    visibility = ["//:sandbox"],
    deps = [
        ":unimplemented_syscall_go_proto",
        "//pkg/abi/linux",
        "//pkg/eventchannel",
        "//pkg/sentry/arch",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/epoll",
        "//pkg/sentry/kernel/kdefs",
        "//pkg/sentry/kernel/time",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)

proto_library(
    name = "unimplemented_syscall_proto",
    srcs = ["unimplemented_syscall.proto"],
    visibility = ["//visibility:public"],
    deps = ["//pkg/sentry/arch:registers_proto"],
)

go_proto_library(
    name = "unimplemented_syscall_go_proto",
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/syscalls/unimplemented_syscall_go_proto",
    proto = ":unimplemented_syscall_proto",
    visibility = ["//visibility:public"],
    deps = ["//pkg/sentry/arch:registers_go_proto"],
)
