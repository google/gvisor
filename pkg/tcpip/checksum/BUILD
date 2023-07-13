load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "checksum_test",
    srcs = ["checksum_test.go"],
    library = ":checksum",
)

go_library(
    name = "checksum",
    srcs = [
        "checksum.go",
        "checksum_amd64.go",
        "checksum_amd64.s",
        "checksum_noasm_unsafe.go",
    ],
    visibility = ["//visibility:public"],
)
