package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "server",
    srcs = ["server.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/control/server",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/unet",
        "//pkg/urpc",
    ],
)
