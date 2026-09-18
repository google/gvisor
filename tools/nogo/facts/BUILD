load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "facts",
    srcs = ["facts.go"],
    visibility = ["//tools:__subpackages__"],
    deps = [
        "//tools/checkconst",
        "@org_golang_x_tools//go/analysis:go_default_library",
        "@org_golang_x_tools//go/types/objectpath:go_default_library",
    ],
)

go_test(
    name = "facts_test",
    size = "small",
    srcs = ["facts_test.go"],
    library = ":facts",
)
