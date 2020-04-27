load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "interrupt",
    srcs = [
        "interrupt.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = ["//pkg/sync"],
)

go_test(
    name = "interrupt_test",
    size = "small",
    srcs = ["interrupt_test.go"],
    library = ":interrupt",
)
