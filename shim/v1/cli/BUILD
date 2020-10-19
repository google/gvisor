load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "cli",
    srcs = [
        "api.go",
        "cli.go",
        "config.go",
    ],
    visibility = [
        "//:__pkg__",
        "//shim/v1:__pkg__",
    ],
    deps = [
        "//pkg/shim/runsc",
        "//pkg/shim/v1/shim",
        "@com_github_burntsushi_toml//:go_default_library",
        "@com_github_containerd_containerd//events:go_default_library",
        "@com_github_containerd_containerd//namespaces:go_default_library",
        "@com_github_containerd_containerd//runtime/v1/shim/v1:go_default_library",
        "@com_github_containerd_containerd//sys:go_default_library",
        "@com_github_containerd_containerd//sys/reaper:go_default_library",
        "@com_github_containerd_ttrpc//:go_default_library",
        "@com_github_containerd_typeurl//:go_default_library",
        "@com_github_gogo_protobuf//types:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
