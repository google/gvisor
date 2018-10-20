package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "syscalls",
    srcs = [
        "epoll.go",
        "polling.go",
        "syscalls.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/syscalls",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/arch",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/epoll",
        "//pkg/sentry/kernel/kdefs",
        "//pkg/sentry/kernel/time",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)
