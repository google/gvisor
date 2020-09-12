load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "socket_refs",
    out = "socket_refs.go",
    package = "unix",
    prefix = "socketOpsCommon",
    template = "//pkg/refs_vfs2:refs_template",
    types = {
        "T": "socketOpsCommon",
    },
)

go_library(
    name = "unix",
    srcs = [
        "device.go",
        "io.go",
        "socket_refs.go",
        "unix.go",
        "unix_vfs2.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/fspath",
        "//pkg/log",
        "//pkg/marshal",
        "//pkg/refs",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/lock",
        "//pkg/sentry/fsimpl/sockfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/socket",
        "//pkg/sentry/socket/control",
        "//pkg/sentry/socket/netstack",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/vfs",
        "//pkg/syserr",
        "//pkg/syserror",
        "//pkg/tcpip",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)
