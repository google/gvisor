load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "port",
    srcs = ["port.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = ["//pkg/sync"],
)

go_test(
    name = "port_test",
    srcs = ["port_test.go"],
    library = ":port",
)
