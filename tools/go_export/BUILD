load("//tools:defs.bzl", "go_binary", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "assemble",
    srcs = ["main.go"],
    visibility = ["//:__pkg__"],
    deps = ["@org_golang_x_mod//modfile:go_default_library"],
)

go_test(
    name = "assemble_test",
    size = "small",
    srcs = [
        "main.go",
        "main_test.go",
    ],
    deps = ["@org_golang_x_mod//modfile:go_default_library"],
)
