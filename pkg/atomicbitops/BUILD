load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "atomicbitops",
    srcs = [
        "atomic_bitops.go",
        "atomic_bitops_amd64.s",
        "atomic_bitops_arm64.s",
        "atomic_bitops_common.go",
    ],
    visibility = ["//:sandbox"],
)

go_test(
    name = "atomicbitops_test",
    size = "small",
    srcs = ["atomic_bitops_test.go"],
    library = ":atomicbitops",
    deps = ["//pkg/sync"],
)
