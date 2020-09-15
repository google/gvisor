load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "testutil",
    srcs = [
        "testutil.go",
    ],
    visibility = ["//pkg/tcpip/network/ipv4:__pkg__"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/stack",
    ],
)
