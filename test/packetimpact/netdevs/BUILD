load("//tools:defs.bzl", "go_library")

package(
    licenses = ["notice"],
)

go_library(
    name = "netdevs",
    srcs = ["netdevs.go"],
    visibility = ["//test/packetimpact:__subpackages__"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
    ],
)
