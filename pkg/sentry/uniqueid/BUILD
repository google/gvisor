load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "uniqueid",
    srcs = ["context.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/uniqueid",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/socket/unix/transport",
    ],
)
