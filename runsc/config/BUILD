load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "config",
    srcs = [
        "config.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/refs",
        "//pkg/sentry/watchdog",
    ],
)
