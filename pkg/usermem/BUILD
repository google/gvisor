load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "usermem",
    srcs = [
        "bytes_io.go",
        "bytes_io_unsafe.go",
        "marshal.go",
        "usermem.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/binary",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/gohacks",
        "//pkg/hostarch",
        "//pkg/safemem",
    ],
)

go_test(
    name = "usermem_test",
    size = "small",
    srcs = [
        "usermem_test.go",
    ],
    library = ":usermem",
    deps = [
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/safemem",
    ],
)
