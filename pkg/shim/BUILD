load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = [":users"],
    licenses = ["notice"],
)

package_group(
    name = "users",
    packages = [
        "//...",
        "//cloud/kubernetes/node/snapshot/...",
    ],
)

go_library(
    name = "shim",
    srcs = ["shim.go"],
)
