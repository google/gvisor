package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "syserr",
    srcs = [
        "host_linux.go",
        "linuxabi.go",
        "netstack.go",
        "syserr.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/syserr",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/syserror",
        "//pkg/tcpip",
    ],
)
