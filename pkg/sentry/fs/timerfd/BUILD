load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "timerfd",
    srcs = ["timerfd.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/anon",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/kernel/time",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)
