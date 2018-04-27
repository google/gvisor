package(licenses = ["notice"])  # BSD

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "buffer_state",
    srcs = [
        "view.go",
    ],
    out = "buffer_state.go",
    package = "buffer",
)

go_library(
    name = "buffer",
    srcs = [
        "buffer_state.go",
        "prependable.go",
        "view.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/buffer",
    visibility = ["//visibility:public"],
    deps = ["//pkg/state"],
)

go_test(
    name = "buffer_test",
    size = "small",
    srcs = ["view_test.go"],
    embed = [":buffer"],
)
