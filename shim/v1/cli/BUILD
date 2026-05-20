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
        "//pkg/shim/v1",
        "//pkg/shim/v1/plugin",
        "@com_github_containerd_containerd_v2//pkg/shim:go_default_library",
    ],
)
