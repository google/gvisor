load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

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
