package(licenses = ["notice"])  # BSD

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "fragmentation_state",
    srcs = ["reassembler_list.go"],
    out = "fragmentation_state.go",
    package = "fragmentation",
)

go_template_instance(
    name = "reassembler_list",
    out = "reassembler_list.go",
    package = "fragmentation",
    prefix = "reassembler",
    template = "//pkg/ilist:generic_list",
    types = {
        "Linker": "*reassembler",
    },
)

go_library(
    name = "fragmentation",
    srcs = [
        "frag_heap.go",
        "fragmentation.go",
        "fragmentation_state.go",
        "reassembler.go",
        "reassembler_list.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/network/fragmentation",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/state",
        "//pkg/tcpip/buffer",
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

filegroup(
    name = "autogen",
    srcs = [
        "reassembler_list.go",
    ],
    visibility = ["//:sandbox"],
)
