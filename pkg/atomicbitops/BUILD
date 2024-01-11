load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "atomicbitops",
    srcs = [
        "32b.go",
        "aligned_386_unsafe.go",
        "aligned_amd64.go",
        "aligned_arm64.go",
        "aligned_arm_unsafe.go",
        "aligned_mips_unsafe.go",
        "aligned_mipsle_unsafe.go",
        "atomicbitops.go",
        "atomicbitops_amd64.s",
        "atomicbitops_arm64.go",
        "atomicbitops_arm64.s",
        "atomicbitops_float64.go",
        "atomicbitops_noasm.go",
        "bool.go",
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
    library = ":atomicbitops",
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

# Generate per-architecture Int64 and Uint64 types for 32 bit architectures.
#
# These types are run through stateify, which currently doesn't gracefully
# handle having one file for 32 bit and one for 64 bit architectures. To avoid
# duplicating code, we generate a version of the file for each supported
# architecture.
genrule(
    name = "aligned32",
    srcs = ["aligned_32bit_unsafe.go"],
    outs = [
        "aligned_386_unsafe.go",
        "aligned_arm_unsafe.go",
        "aligned_mips_unsafe.go",
        "aligned_mipsle_unsafe.go",
    ],
    cmd = """
        for ARCH in 386 arm mips mipsle; do
            sed -e '\\:^// BUILD CONSTRAINTS INSERTED BY GENRULE$$:a \
                    //go:build '"$$ARCH"'\\n// +build '"$$ARCH" \
                    $< > "$(RULEDIR)/aligned_$${ARCH}_unsafe.go"
        done
    """,
)

# Generate per-architecture Int64 and Uint64 types for 64 bit architectures.
#
# These types are run through stateify, which currently doesn't gracefully
# handle having one file for 32 bit and one for 64 bit architectures. To avoid
# duplicating code, we generate a version of the file for each supported
# architecture.
genrule(
    name = "aligned64",
    srcs = ["aligned_64bit.go"],
    outs = [
        "aligned_amd64.go",
        "aligned_arm64.go",
    ],
    cmd = """
        for ARCH in amd64 arm64; do
            sed -e '\\:^// BUILD CONSTRAINTS INSERTED BY GENRULE$$:a \
                    //go:build '"$$ARCH"'\\n// +build '"$$ARCH" \
                    $< > "$(RULEDIR)/aligned_$${ARCH}.go"
        done
    """,
)
