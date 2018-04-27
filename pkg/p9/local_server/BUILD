package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_binary")

go_binary(
    name = "local_server",
    srcs = ["local_server.go"],
    deps = [
        "//pkg/fd",
        "//pkg/log",
        "//pkg/p9",
        "//pkg/unet",
    ],
)
