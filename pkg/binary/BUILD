load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "binary",
    srcs = ["binary.go"],
    visibility = ["//:sandbox"],
)

go_test(
    name = "binary_test",
    size = "small",
    srcs = ["binary_test.go"],
    library = ":binary",
)
