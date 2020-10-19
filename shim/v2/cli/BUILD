load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "cli",
    srcs = ["cli.go"],
    visibility = [
        "//:__pkg__",
        "//shim/v2:__pkg__",
    ],
    deps = [
        "//pkg/shim/v2",
        "@com_github_containerd_containerd//runtime/v2/shim:go_default_library",
    ],
)
