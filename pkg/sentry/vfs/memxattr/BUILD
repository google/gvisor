load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "memxattr",
    srcs = ["xattr.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/sync",
    ],
)
