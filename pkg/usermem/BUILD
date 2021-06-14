load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

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
        "//pkg/context",
        "//pkg/gohacks",
        "//pkg/hostarch",
        "//pkg/safemem",
        "//pkg/syserror",
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
        "//pkg/hostarch",
        "//pkg/safemem",
        "//pkg/syserror",
    ],
)
