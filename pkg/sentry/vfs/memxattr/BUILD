load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "memxattr",
    srcs = ["xattr.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserror",
    ],
)
