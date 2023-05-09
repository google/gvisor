load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "bitmap",
    srcs = ["bitmap.go"],
    visibility = ["//:sandbox"],
)

go_test(
    name = "bitmap_test",
    size = "small",
    srcs = ["bitmap_test.go"],
    library = ":bitmap",
)
