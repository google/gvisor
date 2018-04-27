package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "test_state",
    srcs = [
        "test.go",
    ],
    out = "test_state.go",
    package = "test",
)

go_library(
    name = "test",
    testonly = 1,
    srcs = [
        "test.go",
        "test_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs/test",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/ramfs",
        "//pkg/state",
    ],
)
