package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "transport",
    srcs = [
        "connectioned.go",
        "connectioned_state.go",
        "connectionless.go",
        "queue.go",
        "unix.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix/transport",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/ilist",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/waiter",
    ],
)
