load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "util",
    srcs = [
        "tpu.go",
        "util.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
        "//tools:__subpackages__",
    ],
    deps = [
        "//pkg/abi/tpu",
        "//pkg/log",
        "@com_github_google_subcommands//:go_default_library",
    ],
)
