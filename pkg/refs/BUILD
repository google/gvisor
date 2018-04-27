package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "refs_state",
    srcs = [
        "refcounter.go",
        "refcounter_state.go",
    ],
    out = "refs_state.go",
    package = "refs",
)

go_library(
    name = "refs",
    srcs = [
        "refcounter.go",
        "refcounter_state.go",
        "refs_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/refs",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/ilist",
        "//pkg/log",
        "//pkg/state",
    ],
)

go_test(
    name = "refs_test",
    size = "small",
    srcs = ["refcounter_test.go"],
    embed = [":refs"],
)
