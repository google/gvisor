load("@io_bazel_rules_go//go:def.bzl", "go_binary")
load("@rules_cc//cc:defs.bzl", "cc_binary")

package(licenses = ["notice"])

go_binary(
    name = "tcp_proxy",
    srcs = ["tcp_proxy.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/adapters/gonet",
        "//pkg/tcpip/link/fdbased",
        "//pkg/tcpip/network/arp",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/udp",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

# nsjoin is a trivial replacement for nsenter. This is used because nsenter is
# not available on all systems where this benchmark is run (and we aim to
# minimize external dependencies.)

cc_binary(
    name = "nsjoin",
    srcs = ["nsjoin.c"],
    visibility = ["//:sandbox"],
)

sh_binary(
    name = "tcp_benchmark",
    srcs = ["tcp_benchmark.sh"],
    data = [
        ":nsjoin",
        ":tcp_proxy",
    ],
    visibility = ["//:sandbox"],
)
