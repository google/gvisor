load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])  # Apache 2.0

go_library(
    name = "loopback",
    srcs = ["loopback.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/link/loopback",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/stack",
    ],
)
