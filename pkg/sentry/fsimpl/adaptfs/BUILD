load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "adaptfs",
    srcs = [
        "adaptfs.go",
        "file_description.go",
        "filesystem.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fsimpl/adaptfs",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/fspath",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)
