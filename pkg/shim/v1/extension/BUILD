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
        "//pkg/shim/v1/runsc:hibernate_go_proto",
        "@com_github_containerd_console//:go_default_library",
        "@com_github_containerd_containerd_api//runtime/task/v2:go_default_library",
        "@com_github_containerd_containerd_v2//pkg/stdio:go_default_library",
    ],
)
