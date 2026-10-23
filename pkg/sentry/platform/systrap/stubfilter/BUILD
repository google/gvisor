load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "stubfilter",
    srcs = [
        "stubfilter.go",
        "stubfilter_amd64.go",
        "stubfilter_arm64.go",
    ],
    visibility = ["//pkg/sentry/platform/systrap:__pkg__"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/seccomp",
        "//pkg/seccomp/precompiledseccomp",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
