load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//visibility:public"],
    licenses = ["notice"],
)

go_library(
    name = "p9",
    srcs = [
        "p9.go",
    ],
    deps = [
        "//pkg/abi/linux",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "p9_test",
    size = "small",
    srcs = ["p9_test.go"],
    library = ":p9",
)
