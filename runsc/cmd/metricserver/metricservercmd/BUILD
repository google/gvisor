load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "metricservercmd",
    srcs = ["metricservercmd.go"],
    visibility = [
        "//runsc/cmd:__subpackages__",
    ],
    deps = ["//runsc/flag"],
)
