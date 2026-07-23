load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "gvisorbinaries",
    srcs = ["gvisorbinaries.go"],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/log",
        "//runsc/config",
        "//runsc/specutils",
        "//runsc/version",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
