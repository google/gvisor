load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "atomicbitops",
    srcs = [
        "atomicbitops.go",
        "atomicbitops_amd64.s",
        "atomicbitops_arm64.go",
        "atomicbitops_arm64.s",
        "atomicbitops_noasm.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/cpuid",
        "@org_golang_x_sys//cpu:go_default_library",
    ],
)

go_test(
    name = "atomicbitops_benchmark_test",
    size = "small",
    srcs = ["atomicbitops_benchmark_test.go"],
    library = ":atomicbitops",
)

go_test(
    name = "atomicbitops_test",
    size = "small",
    srcs = ["atomicbitops_test.go"],
    library = ":atomicbitops",
    deps = ["//pkg/sync"],
)
