load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "fuse",
    srcs = ["fuse.go"],
    visibility = ["//test/runner:__subpackages__"],
    deps = [
        "//pkg/log",
        "//runsc/specutils",
        "@com_github_hanwen_go_fuse_v2//fs:go_default_library",
        "@com_github_hanwen_go_fuse_v2//fuse:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
