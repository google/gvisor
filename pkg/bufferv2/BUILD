load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "chunk_refs",
    out = "chunk_refs.go",
    package = "bufferv2",
    prefix = "chunk",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "chunk",
    },
)

go_template_instance(
    name = "view_list",
    out = "view_list.go",
    package = "bufferv2",
    prefix = "view",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*View",
        "Linker": "*View",
    },
)

go_library(
    name = "bufferv2",
    srcs = [
        "buffer.go",
        "buffer_state.go",
        "chunk.go",
        "chunk_refs.go",
        "view.go",
        "view_list.go",
        "view_unsafe.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/bits",
        "//pkg/context",
        "//pkg/ilist",
        "//pkg/log",
        "//pkg/pool",
        "//pkg/refs",
        "//pkg/sync",
        "//pkg/tcpip/checksum",
    ],
)

go_test(
    name = "bufferv2_test",
    srcs = [
        "buffer_test.go",
        "view_test.go",
    ],
    library = ":bufferv2",
    deps = [
        "//pkg/state",
        "//pkg/tcpip/checksum",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)
