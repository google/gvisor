package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

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
        "usermem_x86.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/usermem",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/binary",
        "//pkg/log",
        "//pkg/sentry/context",
        "//pkg/sentry/safemem",
        "//pkg/syserror",
        "//pkg/tcpip/buffer",
    ],
)

go_test(
    name = "usermem_test",
    size = "small",
    srcs = [
        "addr_range_seq_test.go",
        "usermem_test.go",
    ],
    embed = [":usermem"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/safemem",
        "//pkg/syserror",
    ],
)
