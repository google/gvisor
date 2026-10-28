load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "coretagprime",
    srcs = ["coretagprime.go"],
    visibility = [
        "//:__pkg__",
        "//runsc:__subpackages__",
    ],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)

go_test(
    name = "coretagprime_test",
    size = "small",
    srcs = ["coretagprime_test.go"],
    embed = [":coretagprime"],
)
