package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "client",
    srcs = [
        "client.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/control/client",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/unet",
        "//pkg/urpc",
    ],
)
