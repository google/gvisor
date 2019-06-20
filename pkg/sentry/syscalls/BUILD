load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "syscalls",
    srcs = [
        "epoll.go",
        "syscalls.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/syscalls",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/arch",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/epoll",
        "//pkg/sentry/kernel/kdefs",
        "//pkg/sentry/kernel/time",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)
