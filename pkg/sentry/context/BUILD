load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "context",
    srcs = ["context.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/amutex",
        "//pkg/log",
    ],
)
