load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "mmapfilter",
    srcs = ["mmapfilter.go"],
    visibility = ["//pkg/sentry/platform/kvm:__pkg__"],
    deps = [
        "//pkg/seccomp",
        "//pkg/seccomp/precompiledseccomp",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
