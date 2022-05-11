load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "utils",
    srcs = [
        "annotations.go",
        "utils.go",
        "volumes.go",
    ],
    visibility = [
        "//pkg/shim:__subpackages__",
        "//shim:__subpackages__",
    ],
    deps = ["@com_github_opencontainers_runtime_spec//specs-go:go_default_library"],
)

go_test(
    name = "utils_test",
    size = "small",
    srcs = ["volumes_test.go"],
    library = ":utils",
    deps = ["@com_github_opencontainers_runtime_spec//specs-go:go_default_library"],
)
