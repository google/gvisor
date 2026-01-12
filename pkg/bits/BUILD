load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "bits",
    srcs = [
        "bits.go",
        "bits_template.go",
        "uint64_arch.go",
        "uint64_arch_amd64_asm.s",
        "uint64_arch_arm64_asm.s",
        "uint64_arch_generic.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "@org_golang_x_exp//constraints:go_default_library",
    ],
)

go_test(
    name = "bits_test",
    size = "small",
    srcs = ["uint64_test.go"],
    library = ":bits",
)
