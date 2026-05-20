load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "plugin",
    srcs = ["plugin_linux.go"],
    visibility = ["//shim:__subpackages__"],
    deps = [
        "//pkg/shim/v1",  # keep
        "@com_github_containerd_containerd_v2//pkg/shim:go_default_library",
        "@com_github_containerd_containerd_v2//pkg/shutdown:go_default_library",
        "@com_github_containerd_containerd_v2//plugins:go_default_library",
        "@com_github_containerd_plugin//:go_default_library",
        "@com_github_containerd_plugin//registry:go_default_library",
    ],
)
