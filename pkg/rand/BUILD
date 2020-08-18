load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "rand",
    srcs = [
        "rand.go",
        "rand_linux.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
