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
        "frag_heap.go",
        "fragmentation.go",
        "reassembler.go",
        "reassembler_list.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/log",
        "//pkg/sync",
        "//pkg/tcpip",
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
    library = ":fragmentation",
    deps = ["//pkg/tcpip/buffer"],
)
