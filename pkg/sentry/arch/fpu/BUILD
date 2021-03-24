load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "fpu",
    srcs = [
        "fpu.go",
        "fpu_amd64.go",
        "fpu_amd64.s",
        "fpu_arm64.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/cpuid",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
