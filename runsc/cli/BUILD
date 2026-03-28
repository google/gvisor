load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "cli",
    srcs = [
        "cli.go",
        "help.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/coverage",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sync",
        "//runsc/cmd/util",
        "//runsc/config",
        "//runsc/flag",
        "//runsc/specutils",
        "//runsc/starttime",
        "//runsc/version",
        "@com_github_google_subcommands//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
