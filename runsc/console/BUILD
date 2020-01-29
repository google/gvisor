load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "console",
    srcs = [
        "console.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "@com_github_kr_pty//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
