load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "errors",
    srcs = ["errors.go"],
    visibility = ["//:sandbox"],
    deps = ["//pkg/abi/linux/errno"],
)
