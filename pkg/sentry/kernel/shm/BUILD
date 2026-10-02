load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "shm",
    srcs = [
        "context.go",
        "shm.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/ipc",
        "//pkg/sentry/ktime",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/usage",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/usermem",
    ],
)
