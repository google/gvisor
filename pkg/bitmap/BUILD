load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "bitmap",
    srcs = ["bitmap.go"],
    visibility = ["//:sandbox"],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)

go_test(
    name = "bitmap_test",
    size = "small",
    srcs = ["bitmap_test.go"],
    library = ":bitmap",
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
