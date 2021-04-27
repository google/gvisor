load("//tools:defs.bzl", "go_library", "proto_library")

package(licenses = ["notice"])

go_library(
    name = "strace",
    srcs = [
        "capability.go",
        "clone.go",
        "epoll.go",
        "futex.go",
        "linux64_amd64.go",
        "linux64_arm64.go",
        "open.go",
        "poll.go",
        "ptrace.go",
        "select.go",
        "signal.go",
        "socket.go",
        "strace.go",
        "syscalls.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        ":strace_go_proto",
        "//pkg/abi",
        "//pkg/abi/linux",
        "//pkg/bits",
        "//pkg/eventchannel",
        "//pkg/hostarch",
        "//pkg/marshal/primitive",
        "//pkg/seccomp",
        "//pkg/sentry/arch",
        "//pkg/sentry/kernel",
        "//pkg/sentry/socket",
        "//pkg/sentry/socket/netlink",
        "//pkg/sentry/syscalls/linux",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

proto_library(
    name = "strace",
    srcs = ["strace.proto"],
    visibility = ["//visibility:public"],
)
