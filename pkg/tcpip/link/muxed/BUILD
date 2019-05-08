load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(
    licenses = ["notice"],  # Apache 2.0
)

go_library(
    name = "muxed",
    srcs = ["injectable.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/link/muxed",
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
    name = "muxed_test",
    size = "small",
    srcs = ["injectable_test.go"],
    embed = [":muxed"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/link/fdbased",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/stack",
    ],
)
