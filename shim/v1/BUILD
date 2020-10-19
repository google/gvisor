load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "gvisor-containerd-shim",
    srcs = ["main.go"],
    static = True,
    visibility = [
        "//visibility:public",
    ],
    deps = ["//shim/v1/cli"],
)
