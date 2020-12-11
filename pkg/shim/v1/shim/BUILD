load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "shim",
    srcs = [
        "api.go",
        "platform.go",
        "service.go",
        "shim.go",
    ],
    visibility = [
        "//pkg/shim:__subpackages__",
        "//shim:__subpackages__",
    ],
    deps = [
        "//pkg/shim/runsc",
        "//pkg/shim/v1/proc",
        "//pkg/shim/v1/utils",
        "@com_github_containerd_console//:go_default_library",
        "@com_github_containerd_containerd//api/events:go_default_library",
        "@com_github_containerd_containerd//api/types/task:go_default_library",
        "@com_github_containerd_containerd//errdefs:go_default_library",
        "@com_github_containerd_containerd//events:go_default_library",
        "@com_github_containerd_containerd//log:go_default_library",
        "@com_github_containerd_containerd//mount:go_default_library",
        "@com_github_containerd_containerd//namespaces:go_default_library",
        "@com_github_containerd_containerd//pkg/process:go_default_library",
        "@com_github_containerd_containerd//pkg/stdio:go_default_library",
        "@com_github_containerd_containerd//runtime:go_default_library",
        "@com_github_containerd_containerd//runtime/linux/runctypes:go_default_library",
        "@com_github_containerd_containerd//runtime/v1/shim/v1:go_default_library",
        "@com_github_containerd_containerd//sys/reaper:go_default_library",
        "@com_github_containerd_fifo//:go_default_library",
        "@com_github_containerd_typeurl//:go_default_library",
        "@com_github_gogo_protobuf//types:go_default_library",
        "@org_golang_google_grpc//codes:go_default_library",
        "@org_golang_google_grpc//status:go_default_library",
    ],
)
