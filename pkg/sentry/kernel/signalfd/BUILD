load("//tools:defs.bzl", "go_library")
load("//pkg/sync/locking:locking.bzl", "declare_mutex")

licenses(["notice"])

declare_mutex(
    name = "signal_operations_mutex",
    out = "signal_operations_mutex.go",
    package = "signalfd",
    prefix = "operations",
)

go_library(
    name = "signalfd",
    srcs = [
        "signal_operations_mutex.go",
        "signalfd.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/anon",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/kernel",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)
