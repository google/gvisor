load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])  # Apache 2.0

go_library(
    name = "atomicbitops",
    srcs = [
        "atomic_bitops.go",
        "atomic_bitops_amd64.s",
        "atomic_bitops_common.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/atomicbitops",
    visibility = ["//:sandbox"],
)

go_test(
    name = "atomicbitops_test",
    size = "small",
    srcs = ["atomic_bitops_test.go"],
    embed = [":atomicbitops"],
)
