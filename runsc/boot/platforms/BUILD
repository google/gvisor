load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "platforms",
    srcs = ["platforms.go"],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/sentry/platform/kvm",
        "//pkg/sentry/platform/ptrace",
    ],
)
