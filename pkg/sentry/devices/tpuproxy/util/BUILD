load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "util",
    srcs = [
        "ioctl_unsafe.go",
        "util.go",
    ],
    visibility = [
        "//pkg/sentry:internal",
    ],
    deps = [
        "@org_golang_x_exp//constraints:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
