package(licenses = ["notice"])

load("//tools:defs.bzl", "go_library")

go_library(
    name = "plugin",
    srcs = [
        "config.go",
        "plugin.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/seccomp",
        "//pkg/sentry/inet",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
