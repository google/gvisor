load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "errors",
    srcs = ["errors.go"],
    importpath = "gvisor.dev/gvisor/pkg/errors",
    visibility = ["//:sandbox"],
    deps = ["//pkg/abi/linux/errno"],
)
