load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "extraargs",
    srcs = ["extra_args.go"],
    visibility = ["//runsc:__subpackages__"],
    deps = [
        "//pkg/log",
        "//runsc/flag",
    ],
)
