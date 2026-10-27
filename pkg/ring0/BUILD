load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "ring0",
    srcs = [
        "aarch64.go",
        "defs.go",
        "defs_amd64.go",
        "defs_arm64.go",
        "entry_amd64.go",
        "entry_amd64.s",
        "entry_arm64.go",
        "entry_arm64.s",
        "kernel.go",
        "kernel_amd64.go",
        "kernel_arm64.go",
        "kernel_unsafe.go",
        "lib_amd64.go",
        "lib_amd64.s",
        "lib_arm64.go",
        "lib_arm64.s",
        "ring0.go",
        "x86.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/cpuid",
        "//pkg/hostarch",
        "//pkg/ring0/pagetables",
        "//pkg/sentry/arch",
        "//pkg/sentry/arch/fpu",
    ],
)
