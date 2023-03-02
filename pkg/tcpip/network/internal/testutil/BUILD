load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "testutil",
    testonly = True,
    srcs = ["testutil.go"],
    visibility = [
        "//pkg/tcpip/network:__pkg__",
        "//pkg/tcpip/network/arp:__pkg__",
        "//pkg/tcpip/network/internal/fragmentation:__pkg__",
        "//pkg/tcpip/network/ipv4:__pkg__",
        "//pkg/tcpip/network/ipv6:__pkg__",
        "//pkg/tcpip/tests/integration:__pkg__",
    ],
    deps = [
        "//pkg/bufferv2",
        "//pkg/tcpip",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/stack",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)
