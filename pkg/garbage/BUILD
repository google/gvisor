load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "garbage",
    srcs = ["garbage.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/atomicbitops",
    ],
)

go_test(
    name = "garbage_test",
    srcs = ["garbage_test.go"],
    library = ":garbage",
)
