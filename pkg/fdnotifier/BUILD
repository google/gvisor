load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "fdnotifier",
    srcs = [
        "fdnotifier.go",
        "poll_unsafe.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/sync",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
