load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

licenses(["notice"])

go_template_instance(
    name = "inode_refs",
    out = "inode_refs.go",
    package = "host",
    prefix = "inode",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "inode",
    },
)

go_template_instance(
    name = "connected_endpoint_refs",
    out = "connected_endpoint_refs.go",
    package = "host",
    prefix = "ConnectedEndpoint",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "ConnectedEndpoint",
    },
)

go_library(
    name = "host",
    srcs = [
        "connected_endpoint_refs.go",
        "control.go",
        "host.go",
        "host_unsafe.go",
        "inode_refs.go",
        "ioctl_unsafe.go",
        "save_restore.go",
        "socket.go",
        "socket_iovec.go",
        "socket_unsafe.go",
        "tty.go",
        "util.go",
        "util_unsafe.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fdnotifier",
        "//pkg/fspath",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/marshal/primitive",
        "//pkg/refs",
        "//pkg/refsvfs2",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/lock",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/hostfd",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/socket/control",
        "//pkg/sentry/socket/unix",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/unimpl",
        "//pkg/sentry/uniqueid",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserr",
        "//pkg/tcpip",
        "//pkg/unet",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
