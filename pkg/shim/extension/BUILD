load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "extension",
    srcs = ["extension.go"],
    visibility = ["//visibility:public"],
    deps = [
        "@com_github_containerd_containerd//pkg/process:go_default_library",
        "@com_github_containerd_containerd//runtime/v2/task:go_default_library",
    ],
)
