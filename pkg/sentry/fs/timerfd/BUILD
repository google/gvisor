package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "timerfd",
    srcs = ["timerfd.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fs/timerfd",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/anon",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)
