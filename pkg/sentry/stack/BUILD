package(licenses = ["notice"])

load("//tools:defs.bzl", "go_library")

go_library(
    name = "stack",
    srcs = [
        "externalstack.go",
        "notifier.go",
        "util.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/sentry/inet",
        "//pkg/waiter",
    ],
)
