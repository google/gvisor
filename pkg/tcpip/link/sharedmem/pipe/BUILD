load("//tools:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "pipe",
    srcs = [
        "pipe.go",
        "pipe_unsafe.go",
        "rx.go",
        "tx.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/link/sharedmem/pipe",
    visibility = ["//:sandbox"],
)

go_test(
    name = "pipe_test",
    srcs = [
        "pipe_test.go",
    ],
    embed = [":pipe"],
)
