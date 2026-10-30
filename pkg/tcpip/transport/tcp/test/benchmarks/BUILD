load("//tools:defs.bzl", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "netstack_bench_test",
    size = "large",
    srcs = [
        "harness_test.go",
        "netstack_bench_test.go",
    ],
    deps = [
        "//pkg/buffer",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/tcp",
        "//pkg/waiter",
    ],
)
