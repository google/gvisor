load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "nogo",
    srcs = ["nogo.go"],
    nogo = False,
    visibility = [
        "//tools/github:__subpackages__",
    ],
    deps = [
        "//tools/nogo",
        "@com_github_google_go_github_v28//github:go_default_library",
    ],
)
