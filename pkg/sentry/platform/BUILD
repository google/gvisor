load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "platform",
    srcs = [
        "context.go",
        "cpuid_amd64.go",
        "cpuid_arm64.go",
        "mmap_min_addr.go",
        "platform.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/cpuid",
        "//pkg/hostarch",
        "//pkg/seccomp",
        "//pkg/sentry/arch",
        "//pkg/sentry/hostmm",
        "//pkg/sentry/memmap",
        "//pkg/usermem",
    ],
)
