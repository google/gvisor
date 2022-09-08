load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_test(
    name = "checksum_test",
    srcs = ["checksum_test.go"],
    library = ":checksum",
)

go_library(
    name = "checksum",
    srcs = ["checksum.go"],
    visibility = ["//visibility:public"],
)
