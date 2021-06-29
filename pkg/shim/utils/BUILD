load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "utils",
    srcs = [
        "annotations.go",
        "errors.go",
        "utils.go",
        "volumes.go",
    ],
    visibility = [
        "//pkg/shim:__subpackages__",
        "//shim:__subpackages__",
    ],
    deps = [
        "@com_github_containerd_containerd//errdefs:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_google_grpc//codes:go_default_library",
        "@org_golang_google_grpc//status:go_default_library",
    ],
)

go_test(
    name = "utils_test",
    size = "small",
    srcs = [
        "errors_test.go",
        "volumes_test.go",
    ],
    library = ":utils",
    deps = [
        "@com_github_containerd_containerd//errdefs:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)
