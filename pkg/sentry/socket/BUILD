package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_stateify")

go_stateify(
    name = "socket_state",
    srcs = [
        "socket.go",
    ],
    out = "socket_state_autogen.go",
    package = "socket",
)

go_library(
    name = "socket",
    srcs = [
        "socket.go",
        "socket_state_autogen.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/socket",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/kdefs",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/syserr",
        "//pkg/tcpip",
        "//pkg/tcpip/transport/unix",
    ],
)
