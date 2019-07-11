package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "ext",
    srcs = ["ext.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fs/ext",
    visibility = ["//pkg/sentry:internal"],
    deps = ["//pkg/sentry/fs/ext/disklayout"],
)
