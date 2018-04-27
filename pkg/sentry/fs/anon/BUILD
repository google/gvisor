package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "anon",
    srcs = [
        "anon.go",
        "device.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/anon",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/usermem",
    ],
)
