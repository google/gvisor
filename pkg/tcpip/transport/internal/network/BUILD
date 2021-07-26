load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "network",
    srcs = [
        "endpoint.go",
        "endpoint_state.go",
    ],
    visibility = [
        "//pkg/tcpip/transport/raw:__pkg__",
        "//pkg/tcpip/transport/udp:__pkg__",
    ],
    deps = [
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport",
    ],
)
