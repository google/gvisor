load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "fuse",
    srcs = ["fuse.go"],
    visibility = ["//test/runner:__subpackages__"],
    deps = [
        "//pkg/log",
        "@com_github_hanwen_go_fuse_v2//fs:go_default_library",
        "@com_github_hanwen_go_fuse_v2//fuse:go_default_library",
    ],
)
