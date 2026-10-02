load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "nsfs",
    srcs = [
        "nsfs.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/refs",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/ktime",
        "//pkg/sentry/vfs",
        "//pkg/sync",
    ],
)
