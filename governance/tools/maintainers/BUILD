load("//tools:defs.bzl", "go_binary", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "maintainers_gen",
    srcs = ["maintainers_gen.go"],
    deps = ["@in_gopkg_yaml_v3//:go_default_library"],
)

go_test(
    name = "maintainers_test",
    srcs = ["maintainers_test.go"],
    data = [
        ":maintainers_gen",
        "//:.github/reviewer.json",
        "//:MAINTAINERS.md",
        "//governance:maintainers.yaml",
    ],
    deps = ["//pkg/test/testutil"],
)
