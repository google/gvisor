package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "checker",
    testonly = 1,
    srcs = ["checker.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/checker",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
    ],
)
