load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "containerd-shim-runsc-v1",
    srcs = ["main.go"],
    static = True,
    visibility = [
        "//visibility:public",
    ],
    deps = ["//shim/v2/cli"],
)
