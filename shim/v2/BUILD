load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "containerd-shim-runsc-v2",
    srcs = ["main.go"],
    features = ["fully_static_link"],
    tags = ["staging"],
    visibility = [
        "//visibility:public",
    ],
)
