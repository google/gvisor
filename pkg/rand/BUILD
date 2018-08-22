package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "rand",
    srcs = [
        "rand.go",
        "rand_linux.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/rand",
    visibility = ["//:sandbox"],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
