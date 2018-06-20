package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_binary")

go_binary(
    name = "dockercfg",
    srcs = ["dockercfg.go"],
    visibility = [
        "//runsc/test:__subpackages__",
    ],
    deps = ["@com_github_google_subcommands//:go_default_library"],
)
