load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "parser",
    srcs = [
        "auxiliary_files.go",
        "clang_config.go",
        "json_definitions.go",
        "runner.go",
        "sources.go",
    ],
    visibility = [
        "//pkg/sentry/devices/nvproxy:__subpackages__",
        "//tools/nvidia_driver_differ:__subpackages__",
    ],
    deps = [
        "//pkg/sentry/devices/nvproxy",
        "//pkg/sentry/devices/nvproxy/nvconf",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)
