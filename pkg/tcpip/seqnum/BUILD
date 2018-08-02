package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_stateify")

go_stateify(
    name = "seqnum_state",
    srcs = [
        "seqnum.go",
    ],
    out = "seqnum_state.go",
    package = "seqnum",
)

go_library(
    name = "seqnum",
    srcs = [
        "seqnum.go",
        "seqnum_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/seqnum",
    visibility = [
        "//visibility:public",
    ],
    deps = ["//pkg/state"],
)
