package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_stateify")

go_stateify(
    name = "unix_state",
    srcs = [
        "unix.go",
    ],
    out = "unix_state.go",
    package = "unix",
)

go_library(
    name = "unix",
    srcs = [
        "device.go",
        "io.go",
        "unix.go",
        "unix_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/refs",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/kdefs",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/safemem",
        "//pkg/sentry/socket",
        "//pkg/sentry/socket/control",
        "//pkg/sentry/socket/epsocket",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/syserr",
        "//pkg/syserror",
        "//pkg/tcpip",
        "//pkg/tcpip/transport/unix",
        "//pkg/waiter",
    ],
)
