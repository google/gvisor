load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "checkconst",
    srcs = [
        "checkconst.go",
    ],
    nogo = False,
    visibility = ["//tools/nogo:__subpackages__"],
    deps = [
        "@org_golang_x_tools//go/analysis:go_default_library",
    ],
)

go_test(
    name = "checkconst_test",
    size = "small",
    srcs = ["checkconst_test.go"],
    embed = [":checkconst"],
    nogo = False,
)
