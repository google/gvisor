package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "sys",
    srcs = [
        "device.go",
        "devices.go",
        "fs.go",
        "sys.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/sys",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/ramfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
    ],
)
