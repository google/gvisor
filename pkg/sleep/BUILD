load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "sleep",
    srcs = [
        "sleep_unsafe.go",
    ],
    visibility = ["//:sandbox"],
    deps = ["//pkg/sync"],
)

go_test(
    name = "sleep_test",
    size = "medium",
    srcs = [
        "sleep_test.go",
    ],
    library = ":sleep",
    deps = ["//pkg/atomicbitops"],
)
