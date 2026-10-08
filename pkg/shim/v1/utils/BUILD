load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "utils",
    srcs = [
        "annotations.go",
        "fuse.go",
        "utils.go",
        "volumes.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/shim/v1/utils",
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//runsc/specutils",
        "@com_github_containerd_log//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "utils_test",
    size = "small",
    srcs = [
        "fuse_test.go",
        "volumes_test.go",
    ],
    embed = [":utils"],
    deps = [
        "//runsc/specutils",
        "@com_github_mohae_deepcopy//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)
