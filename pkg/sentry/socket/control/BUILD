package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "control",
    srcs = ["control.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/socket/control",
    imports = [
        "gvisor.googlesource.com/gvisor/pkg/sentry/fs",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/kdefs",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
    ],
)
