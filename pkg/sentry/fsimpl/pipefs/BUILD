load("//tools:defs.bzl", "go_library")
load("//pkg/sync/locking:locking.bzl", "declare_mutex", "declare_rwmutex")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

declare_mutex(
    name = "attr_mutex",
    out = "attr_mutex.go",
    package = "pipefs",
    prefix = "attr",
)

go_library(
    name = "pipefs",
    srcs = [
        "attr_mutex.go",
        "pipefs.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fspath",
        "//pkg/hostarch",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/pipe",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/sync/locking",
    ],
)
