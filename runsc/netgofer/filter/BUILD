load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "filter",
    srcs = [
        "config.go",
        "config_amd64.go",
        "config_arm64.go",
        "filter.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/seccomp",
        "//runsc/goferfilter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "filter_test",
    size = "small",
    srcs = ["filter_test.go"],
    library = ":filter",
    deps = [
        "//pkg/seccomp",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
