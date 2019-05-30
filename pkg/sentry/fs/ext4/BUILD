package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "ext4",
    srcs = [
        "device.go",
        "fs.go",
        "inode.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/ext4",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//third_party/goext4",
    ],
)
