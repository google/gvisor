load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "v1",
    srcs = [
        "manager.go",
        "service.go",
    ],
    visibility = [
        "//pkg/shim:__subpackages__",
        "//shim:__subpackages__",
    ],
    deps = [
        "//pkg/cleanup",
        "//pkg/shim/v1/extension",
        "//pkg/shim/v1/proc",
        "//pkg/shim/v1/runsc",
        "//pkg/shim/v1/runsccmd",
        "//pkg/sync",
        "//runsc/specutils",
        "@com_github_containerd_containerd_api//runtime/sandbox/v1:go_default_library",
        "@com_github_containerd_containerd_api//runtime/task/v2:go_default_library",
        "@com_github_containerd_containerd_api//types:go_default_library",
        "@com_github_containerd_containerd_v2//core/mount:go_default_library",
        "@com_github_containerd_containerd_v2//pkg/namespaces:go_default_library",
        "@com_github_containerd_containerd_v2//pkg/protobuf/types:go_default_library",
        "@com_github_containerd_containerd_v2//pkg/shim:go_default_library",
        "@com_github_containerd_containerd_v2//pkg/shutdown:go_default_library",
        "@com_github_containerd_containerd_v2//pkg/sys:go_default_library",
        "@com_github_containerd_errdefs//:go_default_library",
        "@com_github_containerd_errdefs_pkg//errgrpc:go_default_library",
        "@com_github_containerd_log//:go_default_library",
        "@com_github_containerd_ttrpc//:go_default_library",
        "@com_github_containerd_typeurl_v2//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "shim_test",
    srcs = [
        "manager_test.go",
        "service_test.go",
    ],
    library = ":v1",
    deps = [
        "@com_github_containerd_containerd_api//runtime/task/v2:go_default_library",
        "@com_github_containerd_containerd_v2//core/events:go_default_library",
        "@com_github_containerd_containerd_v2//pkg/shim:go_default_library",
        "@com_github_containerd_containerd_v2//pkg/shutdown:go_default_library",
        "@com_github_containerd_typeurl_v2//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go/features:go_default_library",
    ],
)
