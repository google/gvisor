package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "context",
    srcs = ["context.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/context",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/amutex",
        "//pkg/log",
    ],
)
