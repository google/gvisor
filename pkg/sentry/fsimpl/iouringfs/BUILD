load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "iouringfs",
    srcs = ["iouringfs.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/hostarch",
        "//pkg/sentry/vfs",
    ],
)
