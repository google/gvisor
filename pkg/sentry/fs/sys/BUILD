package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "sys",
    srcs = [
        "device.go",
        "devices.go",
        "fs.go",
        "sys.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fs/sys",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/ramfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/usermem",
    ],
)
