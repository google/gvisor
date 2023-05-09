load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "abi",
    srcs = [
        "abi.go",
        "abi_linux.go",
        "flag.go",
    ],
    visibility = ["//:sandbox"],
)
