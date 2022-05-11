load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "proc",
    srcs = [
        "deleted_state.go",
        "exec.go",
        "exec_state.go",
        "init.go",
        "init_state.go",
        "io.go",
        "proc.go",
        "types.go",
        "utils.go",
    ],
    visibility = [
        "//pkg/shim:__subpackages__",
        "//shim:__subpackages__",
    ],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/cleanup",
        "//pkg/shim/runsc",
        "@com_github_containerd_console//:go_default_library",
        "@com_github_containerd_containerd//errdefs:go_default_library",
        "@com_github_containerd_containerd//log:go_default_library",
        "@com_github_containerd_containerd//mount:go_default_library",
        "@com_github_containerd_containerd//pkg/process:go_default_library",
        "@com_github_containerd_containerd//pkg/stdio:go_default_library",
        "@com_github_containerd_fifo//:go_default_library",
        "@com_github_containerd_go_runc//:go_default_library",
        "@com_github_gogo_protobuf//types:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
