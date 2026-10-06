load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "atomicbitops",
    srcs = [
        "32b_32bit.go",
        "32b_64bit.go",
        "aligned_32bit_unsafe.go",
        "aligned_64bit.go",
        "atomicbitops.go",
        "atomicbitops_amd64.s",
        "atomicbitops_arm64.go",
        "atomicbitops_arm64.s",
        "atomicbitops_float64.go",
        "atomicbitops_float64_unsafe.go",
        "atomicbitops_noasm.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/cpuid",
        "//pkg/sync",
        "@org_golang_x_sys//cpu:go_default_library",
    ],
)

go_test(
    name = "atomicbitops_benchmark_test",
    size = "small",
    srcs = ["atomicbitops_benchmark_test.go"],
    embed = [":atomicbitops"],
)

go_test(
    name = "atomicbitops_test",
    size = "small",
    srcs = [
        "aligned_test.go",
        "atomicbitops_test.go",
    ],
    architectures = [
        "amd64",
        "arm64",
    ],
    embed = [":atomicbitops"],
    deps = ["//pkg/sync"],
)

# Explicitly select this suite with native executors for both architectures.
test_suite(
    name = "atomicbitops_test_all_architectures",
    tags = ["manual"],
    tests = [
        ":atomicbitops_test_amd64",
        ":atomicbitops_test_arm64",
        ":atomicbitops_test_nogo",
    ],
)
