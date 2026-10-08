load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "gvisorbinaries",
    srcs = ["gvisorbinaries.go"],
    importpath = "gvisor.dev/gvisor/runsc/gvisorbinaries",
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/log",
        "//pkg/sync",
        "//runsc/config",
        "//runsc/specutils",
        "//runsc/version",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
