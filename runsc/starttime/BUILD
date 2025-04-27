load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "starttime",
    srcs = [
        "starttime.go",
    ],
    visibility = ["//runsc:__subpackages__"],
    deps = ["//pkg/timing"],
)
