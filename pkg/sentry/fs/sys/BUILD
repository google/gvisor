load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "sys",
    srcs = [
        "device.go",
        "devices.go",
        "fs.go",
        "sys.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/hostarch",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/ramfs",
        "//pkg/sentry/kernel",
    ],
)
