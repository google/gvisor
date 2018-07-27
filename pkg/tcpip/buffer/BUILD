package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_stateify", "go_test")

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
