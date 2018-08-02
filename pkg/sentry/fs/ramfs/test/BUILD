package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "test",
    testonly = 1,
    srcs = ["test.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs/test",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/ramfs",
    ],
)
