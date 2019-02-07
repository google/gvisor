load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])  # Apache 2.0

go_library(
    name = "injectable",
    srcs = ["injectable.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/link/injectable",
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "injectable_test",
    size = "small",
    srcs = ["injectable_test.go"],
    embed = [":injectable"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/link/fdbased",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/stack",
    ],
)
