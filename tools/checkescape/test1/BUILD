load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "test1",
    srcs = [
        "test1.go",
        "test1_unsafe.go",
    ],
    stateify = False,
    visibility = ["//tools/checkescape/test2:__pkg__"],
)
