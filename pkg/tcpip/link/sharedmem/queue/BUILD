load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "queue",
    srcs = [
        "rx.go",
        "tx.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/link/sharedmem/queue",
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
