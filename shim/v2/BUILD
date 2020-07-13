load("//tools:defs.bzl", "go_binary")
load("//website:defs.bzl", "doc")

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

doc(
    name = "doc",
    src = "README.md",
    category = "User Guide",
    permalink = "/docs/user_guide/containerd-shim-runsc-v1/",
    subcategory = "Advanced",
    visibility = ["//website:__pkg__"],
    weight = "92",
)
