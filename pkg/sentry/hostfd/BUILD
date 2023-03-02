load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "hostfd",
    srcs = [
        "hostfd.go",
        "hostfd_linux.go",
        "hostfd_unsafe.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/log",
        "//pkg/safemem",
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
