package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "sighandling",
    srcs = [
        "sighandling.go",
        "sighandling_unsafe.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/sighandling",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/arch",
        "//pkg/sentry/kernel",
    ],
)
