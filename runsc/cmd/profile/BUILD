load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "profile",
    srcs = [
        "cpu.go",
        "heap.go",
        "profile.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//runsc/cmd/util",
        "//runsc/config",
        "//runsc/container",
        "//runsc/flag",
        "@com_github_google_subcommands//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)
