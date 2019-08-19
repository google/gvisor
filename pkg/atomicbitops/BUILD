load("//tools:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "atomicbitops",
    srcs = [
        "atomic_bitops.go",
        "atomic_bitops_amd64.s",
        "atomic_bitops_common.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/atomicbitops",
    visibility = ["//:sandbox"],
)

go_test(
    name = "atomicbitops_test",
    size = "small",
    srcs = ["atomic_bitops_test.go"],
    embed = [":atomicbitops"],
)
