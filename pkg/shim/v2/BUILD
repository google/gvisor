load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "v2",
    srcs = [
        "epoll.go",
        "service.go",
        "service_linux.go",
    ],
    visibility = ["//shim:__subpackages__"],
    deps = [
        "//pkg/shim/runsc",
        "//pkg/shim/v1/proc",
        "//pkg/shim/v1/utils",
        "//pkg/shim/v2/options",
        "@com_github_burntsushi_toml//:go_default_library",
        "@com_github_containerd_cgroups//:go_default_library",
        "@com_github_containerd_cgroups//stats/v1:go_default_library",
        "@com_github_containerd_console//:go_default_library",
        "@com_github_containerd_containerd//api/events:go_default_library",
        "@com_github_containerd_containerd//api/types/task:go_default_library",
        "@com_github_containerd_containerd//errdefs:go_default_library",
        "@com_github_containerd_containerd//events:go_default_library",
        "@com_github_containerd_containerd//log:go_default_library",
        "@com_github_containerd_containerd//mount:go_default_library",
        "@com_github_containerd_containerd//namespaces:go_default_library",
        "@com_github_containerd_containerd//runtime:go_default_library",
        "@com_github_containerd_containerd//runtime/linux/runctypes:go_default_library",
        "@com_github_containerd_containerd//runtime/proc:go_default_library",
        "@com_github_containerd_containerd//runtime/v2/shim:go_default_library",
        "@com_github_containerd_containerd//runtime/v2/task:go_default_library",
        "@com_github_containerd_cri//pkg/api/runtimeoptions/v1:go_default_library",
        "@com_github_containerd_fifo//:go_default_library",
        "@com_github_containerd_typeurl//:go_default_library",
        "@com_github_gogo_protobuf//types:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
