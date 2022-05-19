load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "trace",
    srcs = [
        "create.go",
        "delete.go",
        "list.go",
        "metadata.go",
        "procfs.go",
        "trace.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/log",
        "//pkg/sentry/seccheck",
        "//runsc/cmd/util",
        "//runsc/config",
        "//runsc/container",
        "//runsc/flag",
        "@com_github_google_subcommands//:go_default_library",
    ],
)
