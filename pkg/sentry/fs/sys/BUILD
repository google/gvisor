package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_stateify")

go_stateify(
    name = "sys_state",
    srcs = [
        "fs.go",
        "sys.go",
    ],
    out = "sys_state.go",
    package = "sys",
)

go_library(
    name = "sys",
    srcs = [
        "device.go",
        "fs.go",
        "sys.go",
        "sys_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/sys",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/ramfs",
        "//pkg/sentry/usermem",
        "//pkg/state",
    ],
)
