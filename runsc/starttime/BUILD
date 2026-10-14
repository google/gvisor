load("//tools:defs.bzl", "go_library", "go_test")

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

go_test(
    name = "starttime_test",
    size = "small",
    srcs = ["starttime_test.go"],
    embed = [":starttime"],
)
