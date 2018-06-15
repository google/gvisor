package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "dev_state",
    srcs = [
        "dev.go",
        "fs.go",
        "full.go",
        "null.go",
        "random.go",
    ],
    out = "dev_state.go",
    package = "dev",
)

go_library(
    name = "dev",
    srcs = [
        "dev.go",
        "dev_state.go",
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
        "//pkg/amutex",
        "//pkg/log",
        "//pkg/rand",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/ashmem",
        "//pkg/sentry/fs/binder",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/ramfs",
        "//pkg/sentry/fs/tmpfs",
        "//pkg/sentry/memmap",
        "//pkg/sentry/mm",
        "//pkg/sentry/platform",
        "//pkg/sentry/safemem",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/syserror",
    ],
)
