load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "alias",
    srcs = ["aliases.go"],
    visibility = ["//runsc:__subpackages__"],
    deps = [
        "//runsc/cmd/alias/bwrap",
        "//runsc/cmd/util",
    ],
)
