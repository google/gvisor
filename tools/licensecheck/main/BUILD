load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "licensecheck",
    srcs = ["main.go"],
    deps = ["//tools/licensecheck"],
)
