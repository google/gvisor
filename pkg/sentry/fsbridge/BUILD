load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "fsbridge",
    srcs = [
        "bridge.go",
        "vfs.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/fspath",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/vfs",
        "//pkg/usermem",
    ],
)
