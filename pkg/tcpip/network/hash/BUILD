package(licenses = ["notice"])  # BSD

load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "hash",
    srcs = ["hash.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/network/hash",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/rand",
        "//pkg/tcpip/header",
    ],
)
