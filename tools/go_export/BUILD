load("//tools:defs.bzl", "go_binary", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "assemble",
    srcs = ["main.go"],
    visibility = ["//:__pkg__"],
    deps = [
        "//pkg/zip",
        "@org_golang_x_mod//modfile:go_default_library",
    ],
)

go_test(
    name = "assemble_test",
    size = "small",
    srcs = ["main_test.go"],
    embed = [":assemble"],
    deps = ["//pkg/zip"],
)
