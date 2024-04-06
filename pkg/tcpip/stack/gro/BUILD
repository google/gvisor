load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_template_instance(
    name = "gro_packet_list",
    out = "gro_packet_list.go",
    package = "gro",
    prefix = "groPacket",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*groPacket",
        "Linker": "*groPacket",
    },
)

go_library(
    name = "gro",
    srcs = [
        "gro.go",
        "gro_packet_list.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/ilist",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "gro_test",
    size = "small",
    srcs = [
        "gro_test.go",
    ],
    library = ":gro",
)
