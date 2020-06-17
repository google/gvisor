load("//tools:defs.bzl", "go_library", "go_test")

licenses(["notice"])

go_library(
    name = "devpts",
    srcs = [
        "devpts.go",
        "line_discipline.go",
        "master.go",
        "queue.go",
        "slave.go",
        "terminal.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/fs/lock",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/unimpl",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

go_test(
    name = "devpts_test",
    size = "small",
    srcs = ["devpts_test.go"],
    library = ":devpts",
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/contexttest",
        "//pkg/usermem",
    ],
)
