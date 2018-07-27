package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_stateify")

go_stateify(
    name = "control_state",
    srcs = [
        "control.go",
    ],
    out = "control_state.go",
    imports = [
        "gvisor.googlesource.com/gvisor/pkg/sentry/fs",
    ],
    package = "control",
)

go_library(
    name = "control",
    srcs = [
        "control.go",
        "control_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/socket/control",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/kdefs",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/syserror",
        "//pkg/tcpip/transport/unix",
    ],
)
