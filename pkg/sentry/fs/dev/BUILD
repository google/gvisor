package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "dev",
    srcs = [
        "dev.go",
        "device.go",
        "fs.go",
        "full.go",
        "null.go",
        "random.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/dev",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/rand",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/ashmem",
        "//pkg/sentry/fs/binder",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/ramfs",
        "//pkg/sentry/fs/tmpfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/memmap",
        "//pkg/sentry/mm",
        "//pkg/sentry/platform",
        "//pkg/sentry/safemem",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
    ],
)
