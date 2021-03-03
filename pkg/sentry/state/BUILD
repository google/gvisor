load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "state",
    srcs = [
        "state.go",
        "state_metadata.go",
        "state_unsafe.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/log",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/time",
        "//pkg/sentry/vfs",
        "//pkg/sentry/watchdog",
        "//pkg/state/statefile",
        "//pkg/syserror",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
