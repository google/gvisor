load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "fdimport",
    srcs = [
        "console.go",
        "fdimport.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/cleanup",
        "//pkg/context",
        "//pkg/fd",
        "//pkg/fspath",
        "//pkg/sentry/fsimpl/devpts",
        "//pkg/sentry/fsimpl/host",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
