package(licenses = ["notice"])  # BSD

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "waiter_state",
    srcs = [
        "waiter.go",
    ],
    out = "waiter_state.go",
    package = "waiter",
)

go_library(
    name = "waiter",
    srcs = [
        "waiter.go",
        "waiter_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/waiter",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/ilist",
        "//pkg/state",
    ],
)

go_test(
    name = "waiter_test",
    size = "small",
    srcs = [
        "waiter_test.go",
    ],
    embed = [":waiter"],
)
