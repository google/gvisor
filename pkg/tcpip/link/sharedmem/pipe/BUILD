package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "pipe",
    srcs = [
        "pipe.go",
        "pipe_unsafe.go",
        "rx.go",
        "tx.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/link/sharedmem/pipe",
    visibility = ["//:sandbox"],
)

go_test(
    name = "pipe_test",
    srcs = [
        "pipe_test.go",
    ],
    embed = [":pipe"],
)
