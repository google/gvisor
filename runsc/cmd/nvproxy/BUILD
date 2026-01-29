load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "nvproxy",
    srcs = [
        "list_supported_drivers.go",
        "nvproxy.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/sentry/devices/nvproxy",
        "//runsc/config",
        "//runsc/flag",
        "@com_github_google_subcommands//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)
