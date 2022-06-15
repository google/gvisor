load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "config",
    testonly = 1,
    srcs = ["config.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/sentry/seccheck",
        "//runsc/boot",
    ],
)
