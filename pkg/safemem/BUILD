load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "safemem",
    srcs = [
        "block_unsafe.go",
        "io.go",
        "safemem.go",
        "seq_unsafe.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/gohacks",
        "//pkg/safecopy",
    ],
)

go_test(
    name = "safemem_test",
    size = "small",
    srcs = [
        "io_test.go",
        "seq_test.go",
    ],
    library = ":safemem",
)
