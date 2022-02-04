load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "cli",
    srcs = ["cli.go"],
    visibility = ["//tools:__subpackages__"],
    deps = [
        "//runsc/flag",
        "//tools/nogo/check",
        "//tools/nogo/config",
        "//tools/nogo/facts",
        "//tools/nogo/flags",
        "@com_github_google_subcommands//:go_default_library",
        "@in_gopkg_yaml_v2//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
