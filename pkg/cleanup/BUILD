load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "cleanup",
    srcs = ["cleanup.go"],
    visibility = ["//:sandbox"],
    deps = [
    ],
)

go_test(
    name = "cleanup_test",
    srcs = ["cleanup_test.go"],
    library = ":cleanup",
)
