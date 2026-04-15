load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "extension",
    srcs = ["extension.go"],
    visibility = ["//runsc:__subpackages__"],
    deps = [
        "//pkg/lisafs",
        "//pkg/seccomp",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)

go_test(
    name = "extension_test",
    size = "small",
    srcs = ["extension_test.go"],
    library = ":extension",
    deps = [
        "//pkg/lisafs",
        "//pkg/seccomp",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)
