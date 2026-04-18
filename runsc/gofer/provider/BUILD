load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "provider",
    srcs = ["provider.go"],
    visibility = ["//runsc:__subpackages__"],
    deps = [
        "//pkg/lisafs",
        "//pkg/seccomp",
        "//runsc/specutils",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)

go_test(
    name = "provider_test",
    size = "small",
    srcs = ["provider_test.go"],
    library = ":provider",
    deps = [
        "//pkg/lisafs",
        "//pkg/seccomp",
        "//runsc/specutils",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)
