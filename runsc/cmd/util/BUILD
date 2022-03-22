load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "util",
    srcs = ["util.go"],
    visibility = [
        "//runsc/cli:__subpackages__",
        "//runsc/cmd:__subpackages__",
    ],
    deps = [
        "//pkg/log",
        "@com_github_google_subcommands//:go_default_library",
    ],
)
