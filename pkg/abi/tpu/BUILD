load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "tpu",
    srcs = ["tpu.go"],
    hostlayout = True,
    visibility = ["//pkg/sentry:internal"],
)
