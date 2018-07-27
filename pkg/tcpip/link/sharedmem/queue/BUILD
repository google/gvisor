package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "queue",
    srcs = [
        "rx.go",
        "tx.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/link/sharedmem/queue",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/tcpip/link/sharedmem/pipe",
    ],
)

go_test(
    name = "queue_test",
    srcs = [
        "queue_test.go",
    ],
    embed = [":queue"],
    deps = [
        "//pkg/tcpip/link/sharedmem/pipe",
    ],
)
