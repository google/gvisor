load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "v1",
    srcs = ["service.go"],
    visibility = ["//shim:__subpackages__"],
    deps = [
        "//pkg/cleanup",
        "//pkg/shim/v1/extension",
        "//pkg/shim/v1/runsc",
        "//pkg/sync",
        "@com_github_containerd_containerd//namespaces:go_default_library",
        "@com_github_containerd_containerd//runtime/v2/shim:go_default_library",
        "@com_github_containerd_containerd//runtime/v2/task:go_default_library",
        "@com_github_containerd_containerd//sys:go_default_library",
        "@com_github_containerd_errdefs//:go_default_library",
        "@com_github_containerd_log//:go_default_library",
        "@com_github_gogo_protobuf//types:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
