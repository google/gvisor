load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "queue",
    srcs = [
        "rx.go",
        "tx.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/log",
        "//pkg/tcpip/link/sharedmem/pipe",
    ],
)

go_test(
    name = "queue_test",
    srcs = [
        "queue_test.go",
    ],
    library = ":queue",
    deps = [
        "//pkg/atomicbitops",
        "//pkg/tcpip/link/sharedmem/pipe",
    ],
)
