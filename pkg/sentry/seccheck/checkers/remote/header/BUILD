load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "header",
    srcs = ["header.go"],
    marshal = True,
    visibility = ["//:sandbox"],
)

go_test(
    name = "header_test",
    size = "small",
    srcs = ["header_test.go"],
    library = ":header",
)
