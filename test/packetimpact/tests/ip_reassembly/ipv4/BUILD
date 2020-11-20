package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

go_library(
    name = "ipv4",
    srcs = ["ipv4.go"],
    deps = [
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "//test/packetimpact/tests/ip_reassembly/common",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)
