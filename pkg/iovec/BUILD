load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "iovec",
    srcs = [
        "iovec.go",
        "iovec_max.go",
    ],
    visibility = ["//:sandbox"],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)

go_test(
    name = "iovec_test",
    size = "small",
    srcs = ["iovec_test.go"],
    library = ":iovec",
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
