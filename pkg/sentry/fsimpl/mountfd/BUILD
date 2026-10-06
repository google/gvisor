load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "mountfd",
    srcs = ["mountfd.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fsimpl/mountfd",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/context",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
    ],
)
