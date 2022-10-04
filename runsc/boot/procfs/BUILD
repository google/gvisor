load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "procfs",
    srcs = ["dump.go"],
    visibility = ["//runsc:__subpackages__"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/sentry/fsimpl/proc",
        "//pkg/sentry/kernel",
        "//pkg/sentry/limits",
        "//pkg/sentry/mm",
        "//pkg/sentry/vfs",
    ],
)
