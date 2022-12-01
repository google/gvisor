load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "reassembler_list",
    out = "reassembler_list.go",
    package = "fragmentation",
    prefix = "reassembler",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*reassembler",
        "Linker": "*reassembler",
    },
)

go_library(
    name = "fragmentation",
    srcs = [
        "fragmentation.go",
        "reassembler.go",
        "reassembler_list.go",
    ],
    visibility = [
        "//pkg/tcpip/network/ipv4:__pkg__",
        "//pkg/tcpip/network/ipv6:__pkg__",
    ],
    deps = [
        "//pkg/bufferv2",
        "//pkg/log",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "fragmentation_test",
    size = "small",
    srcs = [
        "fragmentation_test.go",
        "main_test.go",
        "reassembler_test.go",
    ],
    library = ":fragmentation",
    deps = [
        "//pkg/bufferv2",
        "//pkg/refs",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/network/internal/testutil",
        "//pkg/tcpip/stack",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)
