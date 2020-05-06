load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "utils",
    srcs = [
        "utils.go",
        "volumes.go",
    ],
    visibility = [
        "//pkg/shim:__subpackages__",
        "//shim:__subpackages__",
    ],
    deps = [
        "@com_github_containerd_cri//pkg/annotations:go_default_library",
        "@com_github_opencontainers_runtime-spec//specs-go:go_default_library",
    ],
)

go_test(
    name = "utils_test",
    size = "small",
    srcs = ["volumes_test.go"],
    library = ":utils",
)
