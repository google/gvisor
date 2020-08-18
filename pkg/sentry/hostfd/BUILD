load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "hostfd",
    srcs = [
        "hostfd.go",
        "hostfd_unsafe.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/safemem",
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
