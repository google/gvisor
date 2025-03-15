load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "extension",
    srcs = ["extension.go"],
    deps = [
        "//pkg/shim",
        "@com_github_containerd_containerd_api//runtime/task/v3:go_default_library",
        "@com_github_containerd_containerd_v2//cmd/containerd-shim-runc-v2/process:go_default_library",
    ],
)
