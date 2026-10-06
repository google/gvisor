load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "tcp",
    srcs = ["tcp.go"],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/internal/tcp",
    visibility = ["//pkg/tcpip:__subpackages__"],
    deps = [
        "//pkg/tcpip",
    ],
)
