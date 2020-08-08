load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "containerd-shim-runsc-v1",
    srcs = [
        "main.go",
    ],
    static = True,
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/shim/v2",
        "@com_github_containerd_containerd//runtime/v2/shim:go_default_library",
    ],
)
