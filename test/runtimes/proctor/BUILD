load("//tools:defs.bzl", "go_binary", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "proctor",
    srcs = ["main.go"],
    stateify = False,
    visibility = ["//test:__subpackages__"],
    deps = [
        "//test/runtimes/proctor/lib",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_binary(
    name = "proctor_bin",
    srcs = ["cmd.go"],
    static = True,
    visibility = ["//test:__subpackages__"],
    deps = [":proctor"],
)
