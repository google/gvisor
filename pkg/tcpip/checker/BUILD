load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "checker",
    testonly = 1,
    srcs = ["checker.go"],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/checker",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
    ],
)
