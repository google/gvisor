load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

package(licenses = ["notice"])

go_library(
    name = "strace",
    srcs = [
        "capability.go",
        "clone.go",
        "futex.go",
        "linux64.go",
        "open.go",
        "ptrace.go",
        "signal.go",
        "socket.go",
        "strace.go",
        "syscalls.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/strace",
    visibility = ["//:sandbox"],
    deps = [
        ":strace_go_proto",
        "//pkg/abi",
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/bits",
        "//pkg/eventchannel",
        "//pkg/seccomp",
        "//pkg/sentry/arch",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/kdefs",
        "//pkg/sentry/socket/control",
        "//pkg/sentry/socket/epsocket",
        "//pkg/sentry/socket/netlink",
        "//pkg/sentry/syscalls/linux",
        "//pkg/sentry/usermem",
    ],
)

proto_library(
    name = "strace_proto",
    srcs = ["strace.proto"],
    visibility = ["//visibility:public"],
)

go_proto_library(
    name = "strace_go_proto",
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/strace/strace_go_proto",
    proto = ":strace_proto",
    visibility = ["//visibility:public"],
)
