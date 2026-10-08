load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "uniqueid",
    srcs = ["context.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/uniqueid",
    visibility = ["//pkg/sentry:internal"],
    deps = ["//pkg/context"],
)
