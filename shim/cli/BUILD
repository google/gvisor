load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "cli",
    srcs = ["cli.go"],
    visibility = [
        "//:__pkg__",
        "//shim:__pkg__",
    ],
    deps = [
        "//pkg/shim",
        "@com_github_containerd_containerd//runtime/v2/shim:go_default_library",
    ],
)
