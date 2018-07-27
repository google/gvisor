package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_stateify")

go_stateify(
    name = "abi_state",
    srcs = [
        "abi.go",
    ],
    out = "abi_state.go",
    package = "abi",
)

go_library(
    name = "abi",
    srcs = [
        "abi.go",
        "abi_state.go",
        "flag.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/abi",
    visibility = ["//:sandbox"],
    deps = ["//pkg/state"],
)
