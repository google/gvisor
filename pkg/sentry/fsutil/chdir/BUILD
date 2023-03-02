load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "chdir",
    srcs = ["chdir.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
