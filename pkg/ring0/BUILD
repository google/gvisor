load("//tools:defs.bzl", "arch_genrule", "go_library", "select_arch")
load("//tools/nogo:defs.bzl", "nogo_facts")

package(licenses = ["notice"])

exports_files(glob(["*.go"]))

nogo_facts(
    name = "entry_impl",
    srcs = [
        "aarch64.go",
        "defs.go",
        "defs_amd64.go",
        "defs_arm64.go",
        "entry_template.go",
        "x86.go",
    ],
    output = "entry_impl.s",
    template = select_arch(
        amd64 = "entry_amd64.s",
        arm64 = "entry_arm64.s",
    ),
    deps = [
        "//pkg/abi/linux",
        "//pkg/cpuid",
        "//pkg/hostarch",
        "//pkg/ring0/pagetables",
        "//pkg/sentry/arch",
        "//pkg/sentry/arch/fpu",
    ],
)

arch_genrule(
    name = "entry_impl_arch",
    src = ":entry_impl",
    template = "entry_impl_%s.s",
)

go_library(
    name = "ring0",
    srcs = [
        "aarch64.go",
        "defs.go",
        "defs_amd64.go",
        "defs_arm64.go",
        "entry_amd64.go",
        "entry_arm64.go",
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
        ":entry_impl_arch",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/cpuid",
        "//pkg/hostarch",
        "//pkg/ring0/pagetables",
        "//pkg/sentry/arch",
        "//pkg/sentry/arch/fpu",
    ],
)
