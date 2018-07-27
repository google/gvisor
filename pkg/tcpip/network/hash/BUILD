package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

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
