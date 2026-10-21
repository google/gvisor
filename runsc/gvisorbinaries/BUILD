load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "gvisorbinaries_test",
    size = "small",
    srcs = ["gvisorbinaries_test.go"],
    embed = [":gvisorbinaries"],
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
