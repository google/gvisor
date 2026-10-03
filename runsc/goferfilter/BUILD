load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "goferfilter",
    srcs = [
        "config_cgo.go",
        "config_profile.go",
        "extra_filters.go",
        "extra_filters_msan.go",
        "extra_filters_race.go",
        "extra_filters_race_amd64.go",
        "extra_filters_race_arm64.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/log",
        "//pkg/seccomp",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
