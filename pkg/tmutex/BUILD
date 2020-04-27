load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "tmutex",
    srcs = ["tmutex.go"],
    visibility = ["//:sandbox"],
)

go_test(
    name = "tmutex_test",
    size = "medium",
    srcs = ["tmutex_test.go"],
    library = ":tmutex",
    deps = ["//pkg/sync"],
)
