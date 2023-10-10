load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "secbenchdef",
    srcs = [
        "secbenchdef.go",
        "special_unsafe.go",
    ],
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bpf",
        "//pkg/seccomp",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
