package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "contexttest_state",
    srcs = [
        "contexttest.go",
    ],
    out = "contexttest_state.go",
    package = "contexttest",
)

go_library(
    name = "contexttest",
    testonly = 1,
    srcs = [
        "contexttest.go",
        "contexttest_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/context/contexttest",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/limits",
        "//pkg/sentry/platform",
        "//pkg/sentry/platform/ptrace",
        "//pkg/sentry/uniqueid",
        "//pkg/state",
    ],
)
