load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "procfs",
    srcs = ["dump.go"],
    visibility = ["//runsc:__subpackages__"],
    deps = [
        "//pkg/context",
        "//pkg/log",
        "//pkg/sentry/kernel",
        "//pkg/sentry/mm",
    ],
)
