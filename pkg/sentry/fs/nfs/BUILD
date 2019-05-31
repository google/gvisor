package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "nfs",
    srcs = ["fs.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/nfs",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
    ],
)
