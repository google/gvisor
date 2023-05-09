load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "pipe",
    srcs = [
        "pipe.go",
        "pipe_unsafe.go",
        "rx.go",
        "tx.go",
    ],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/atomicbitops",
    ],
)

go_test(
    name = "pipe_test",
    srcs = [
        "pipe_test.go",
    ],
    library = ":pipe",
    deps = ["//pkg/sync"],
)
