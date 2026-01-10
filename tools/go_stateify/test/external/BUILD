load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "external",
    srcs = ["external.go"],
    visibility = ["//tools/go_stateify/test:__pkg__"],
    deps = [
        "//pkg/state",
    ],
)
