package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "refs",
    srcs = [
        "refcounter.go",
        "refcounter_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/refs",
    visibility = ["//:sandbox"],
    deps = ["//pkg/ilist"],
)

go_test(
    name = "refs_test",
    size = "small",
    srcs = ["refcounter_test.go"],
    embed = [":refs"],
)
