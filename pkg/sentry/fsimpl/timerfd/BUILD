load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "timerfd",
    srcs = ["timerfd.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/vfs",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)
