load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "control",
    srcs = [
        "control.go",
        "control_vfs2.go",
    ],
    imports = [
        "gvisor.dev/gvisor/pkg/sentry/fs",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bits",
        "//pkg/context",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/socket",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/tcpip",
        "//pkg/usermem",
    ],
)
