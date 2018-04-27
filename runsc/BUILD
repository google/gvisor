package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_binary")

go_binary(
    name = "runsc",
    srcs = [
        "main.go",
    ],
    pure = "on",
    deps = [
        "//pkg/log",
        "//runsc/boot",
        "//runsc/cmd",
        "@com_github_google_subcommands//:go_default_library",
    ],
)
