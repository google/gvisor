load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "atomicbitops",
    srcs = [
        "aligned_32bit_unsafe.go",
        "aligned_64bit.go",
        "atomicbitops.go",
        "atomicbitops_amd64.s",
        "atomicbitops_arm64.s",
        "atomicbitops_noasm.go",
    ],
    visibility = ["//:sandbox"],
)

go_test(
    name = "atomicbitops_test",
    size = "small",
    srcs = [
        "aligned_test.go",
        "atomicbitops_test.go",
    ],
    library = ":atomicbitops",
    deps = ["//pkg/sync"],
)
