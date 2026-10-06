load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "config",
    testonly = 1,
    srcs = ["config.go"],
    importpath = "gvisor.dev/gvisor/test/trace/config",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/sentry/seccheck",
        "//runsc/boot",
    ],
)
