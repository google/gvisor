load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "fdimport",
    srcs = [
        "fdimport.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/context",
        "//pkg/fd",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/host",
        "//pkg/sentry/fsimpl/host",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
    ],
)
