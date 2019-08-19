load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "context",
    srcs = ["context.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/context",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/amutex",
        "//pkg/log",
    ],
)
