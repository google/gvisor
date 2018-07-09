package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "unix_state",
    srcs = [
        "connectioned.go",
        "connectionless.go",
        "unix.go",
    ],
    out = "unix_state.go",
    package = "unix",
)

go_library(
    name = "unix",
    srcs = [
        "connectioned.go",
        "connectioned_state.go",
        "connectionless.go",
        "unix.go",
        "unix_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/transport/unix",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/ilist",
        "//pkg/log",
        "//pkg/state",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/transport/queue",
        "//pkg/waiter",
    ],
)
