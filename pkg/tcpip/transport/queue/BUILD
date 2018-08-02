package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "queue",
    srcs = ["queue.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/transport/queue",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/ilist",
        "//pkg/tcpip",
        "//pkg/waiter",
    ],
)
