load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "secio",
    srcs = [
        "full_reader.go",
        "secio.go",
    ],
    visibility = ["//pkg/sentry:internal"],
)

go_test(
    name = "secio_test",
    size = "small",
    srcs = ["secio_test.go"],
    library = ":secio",
)
