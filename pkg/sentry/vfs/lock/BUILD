load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "lock",
    srcs = ["lock.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sentry/fs/lock",
        "//pkg/syserror",
    ],
)
