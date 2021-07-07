load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "dev",
    srcs = [
        "dev.go",
        "device.go",
        "fs.go",
        "full.go",
        "net_tun.go",
        "null.go",
        "random.go",
        "tty.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/rand",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/ramfs",
        "//pkg/sentry/fs/tmpfs",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/memmap",
        "//pkg/sentry/mm",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/socket/netstack",
        "//pkg/tcpip/link/tun",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)
