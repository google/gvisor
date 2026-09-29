load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "gtest",
    srcs = ["gtest.go"],
    visibility = ["//:sandbox"],
)

go_test(
    name = "gtest_test",
    size = "small",
    srcs = ["gtest_test.go"],
    data = ["//test/util:posix_error_test"],
    library = ":gtest",
    deps = ["//pkg/test/testutil"],
)
