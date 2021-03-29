load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "anon",
    srcs = [
        "anon.go",
        "device.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/hostarch",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
    ],
)
