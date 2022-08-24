load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "profile",
    srcs = ["profile.go"],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/log",
        "//pkg/sentry/control",
        "//runsc/flag",
    ],
)
