load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "example",
    srcs = ["example.go"],
    visibility = [
        "//pkg/seccomp/precompiledseccomp/example:__subpackages__",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/seccomp",
        "//pkg/seccomp/precompiledseccomp",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
