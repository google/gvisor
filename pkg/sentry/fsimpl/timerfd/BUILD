load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "timerfd",
    srcs = ["timerfd.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fsimpl/timerfd",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/ktime",
        "//pkg/sentry/vfs",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)
