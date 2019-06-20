load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "loopback",
    srcs = ["loopback.go"],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/link/loopback",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/stack",
    ],
)
