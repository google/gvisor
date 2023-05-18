load("//tools:defs.bzl", "go_library")
load("//pkg/sync/locking:locking.bzl", "declare_mutex")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_mutex(
    name = "reg_mutex",
    out = "reg_mutex.go",
    package = "fasync",
    prefix = "reg",
)

declare_mutex(
    name = "file_mutex",
    out = "file_mutex.go",
    package = "fasync",
    prefix = "file",
)

go_library(
    name = "fasync",
    srcs = [
        "fasync.go",
        "file_mutex.go",
        "reg_mutex.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/waiter",
    ],
)
