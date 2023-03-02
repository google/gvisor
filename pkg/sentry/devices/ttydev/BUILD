load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "ttydev",
    srcs = ["ttydev.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/fsimpl/devtmpfs",
        "//pkg/sentry/vfs",
    ],
)
