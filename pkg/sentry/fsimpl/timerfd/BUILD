load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "timerfd",
    srcs = ["timerfd.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)
