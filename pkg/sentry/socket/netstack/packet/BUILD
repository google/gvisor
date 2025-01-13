load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "packet",
    srcs = ["ring_buffer.go"],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/buffer",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/marshal",
        "//pkg/safemem",
        "//pkg/sentry/fsutil",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/usage",
        "//pkg/sync",
        "//pkg/tcpip",
    ],
)
