load("//tools:defs.bzl", "go_binary", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "gvisor2pcap",
    srcs = [
        "main.go",
    ],
    features = ["fully_static_link"],
    deps = [
        "//pkg/buffer",
        "//pkg/log",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "gvisor2pcap_test",
    srcs = ["gvisor2pcap_test.go"],
    data = [
        "wget.log",
        "wget6.log",
        ":gvisor2pcap",
    ],
    deps = [
        "//pkg/buffer",
        "//pkg/log",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/stack",
        "//pkg/test/testutil",
    ],
)
