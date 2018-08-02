package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "unix",
    srcs = [
        "connectioned.go",
        "connectioned_state.go",
        "connectionless.go",
        "unix.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/transport/unix",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/ilist",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/transport/queue",
        "//pkg/waiter",
    ],
)
