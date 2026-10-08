load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "checksum_test",
    srcs = ["checksum_test.go"],
    embed = [":checksum"],
)

go_library(
    name = "checksum",
    srcs = [
        "checksum.go",
        "checksum_unsafe.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/checksum",
    visibility = ["//visibility:public"],
)
