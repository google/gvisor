package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "time_state",
    srcs = [
        "time.go",
    ],
    out = "time_state.go",
    package = "time",
)

go_library(
    name = "time",
    srcs = [
        "context.go",
        "time.go",
        "time_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/sentry/context",
        "//pkg/state",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)
