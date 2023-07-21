load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "accel",
    srcs = [
        "accel.go",
        "device.go",
        "seccomp_filters.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/gasket",
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/seccomp",
        "//pkg/sentry/arch",
        "//pkg/sentry/fsimpl/devtmpfs",
        "//pkg/sentry/vfs",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
