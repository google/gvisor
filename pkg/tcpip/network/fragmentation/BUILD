load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library")

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
        "frag_heap.go",
        "fragmentation.go",
        "reassembler.go",
        "reassembler_list.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/network/fragmentation",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/log",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/header",
    ],
)

go_test(
    name = "fragmentation_test",
    size = "small",
    srcs = [
        "frag_heap_test.go",
        "fragmentation_test.go",
        "reassembler_test.go",
    ],
    embed = [":fragmentation"],
    deps = ["//pkg/tcpip/buffer"],
)
