load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "genericproxy",
    srcs = [
        "genericproxy.go",
    ],
    visibility = [
        "//pkg/sentry:internal",
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/sentry/devices/rdmaproxy",
        "//pkg/sentry/kernel",
    ],
)
