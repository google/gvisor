load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "hash",
    srcs = ["hash.go"],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/network/hash",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/rand",
        "//pkg/tcpip/header",
    ],
)
