package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "buffer",
    srcs = [
        "prependable.go",
        "view.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/buffer",
    visibility = ["//visibility:public"],
)

go_test(
    name = "buffer_test",
    size = "small",
    srcs = ["view_test.go"],
    embed = [":buffer"],
)
