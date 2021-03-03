load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "addr_range",
    out = "addr_range.go",
    package = "usermem",
    prefix = "Addr",
    template = "//pkg/segment:generic_range",
    types = {
        "T": "Addr",
    },
)

go_library(
    name = "usermem",
    srcs = [
        "access_type.go",
        "addr.go",
        "addr_range.go",
        "addr_range_seq_unsafe.go",
        "bytes_io.go",
        "bytes_io_unsafe.go",
        "usermem.go",
        "usermem_arm64.go",
        "usermem_x86.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/binary",
        "//pkg/context",
        "//pkg/gohacks",
        "//pkg/log",
        "//pkg/safemem",
        "//pkg/syserror",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "usermem_test",
    size = "small",
    srcs = [
        "addr_range_seq_test.go",
        "usermem_test.go",
    ],
    library = ":usermem",
    deps = [
        "//pkg/context",
        "//pkg/safemem",
        "//pkg/syserror",
    ],
)
