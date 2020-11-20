package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

go_library(
    name = "ipv6",
    srcs = ["ipv6.go"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "//test/packetimpact/tests/ip_reassembly/common",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)
