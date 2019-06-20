package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "ext4",
    srcs = ["fs.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fs/ext4",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
    ],
)
