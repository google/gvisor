load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "null",
    srcs = ["null.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/fd",
        "//pkg/sentry/seccheck",
    ],
)
