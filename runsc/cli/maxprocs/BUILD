load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "maxprocs",
    srcs = ["maxprocs.go"],
    stateify = False,
    visibility = ["//runsc:__subpackages__"],
    deps = ["//pkg/gohacks"],
)

go_test(
    name = "maxprocs_test",
    size = "small",
    srcs = ["maxprocs_test.go"],
    embed = [":maxprocs"],
    deps = ["//pkg/gohacks"],
)
