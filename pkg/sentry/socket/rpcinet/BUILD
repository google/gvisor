package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

go_library(
    name = "rpcinet",
    srcs = [
        "device.go",
        "rpcinet.go",
        "socket.go",
        "stack.go",
        "stack_unsafe.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/socket/rpcinet",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        ":syscall_rpc_go_proto",
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/kdefs",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/socket",
        "//pkg/sentry/socket/hostinet",
        "//pkg/sentry/socket/rpcinet/conn",
        "//pkg/sentry/socket/rpcinet/notifier",
        "//pkg/sentry/usermem",
        "//pkg/syserr",
        "//pkg/syserror",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/transport/unix",
        "//pkg/unet",
        "//pkg/waiter",
    ],
)

proto_library(
    name = "syscall_rpc_proto",
    srcs = ["syscall_rpc.proto"],
    visibility = [
        "//visibility:public",
    ],
)

go_proto_library(
    name = "syscall_rpc_go_proto",
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/socket/rpcinet/syscall_rpc_go_proto",
    proto = ":syscall_rpc_proto",
    visibility = [
        "//visibility:public",
    ],
)
