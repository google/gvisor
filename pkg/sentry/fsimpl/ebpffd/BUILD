load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "ebpffd",
    srcs = [
        "ebpffd.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/context",
        "//pkg/ebpf",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
    ],
)
