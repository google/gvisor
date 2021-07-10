load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "syscalls",
    srcs = [
        "epoll.go",
        "syscalls.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/arch",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/epoll",
        "//pkg/sentry/kernel/time",
        "//pkg/waiter",
    ],
)
