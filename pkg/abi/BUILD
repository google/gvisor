package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "abi",
    srcs = [
        "abi.go",
        "abi_linux.go",
        "flag.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/abi",
    visibility = ["//:sandbox"],
)
