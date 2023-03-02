load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "compressio",
    srcs = ["compressio.go"],
    visibility = ["//:sandbox"],
    deps = ["//pkg/sync"],
)

go_test(
    name = "compressio_test",
    size = "medium",
    srcs = ["compressio_test.go"],
    library = ":compressio",
)
