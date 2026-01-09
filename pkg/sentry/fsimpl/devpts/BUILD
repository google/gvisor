load("//tools:defs.bzl", "go_library", "go_test")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "devpts",
    srcs = [
        "devpts.go",
        "line_discipline.go",
        "master.go",
        "queue.go",
        "replica.go",
        "terminal.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/log",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
        "//pkg/refs",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/fsimpl/lock",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/unimpl",
        "//pkg/sentry/vfs",
        "//pkg/sync",
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
        "//pkg/waiter",
    ],
)
