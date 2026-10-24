load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

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
        "//pkg/fd",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/pinring",
        "//pkg/seccomp",
        "//pkg/seccomp/precompiledseccomp",
        "//pkg/sentry/arch",
        "//pkg/sentry/hostmm",
        "//pkg/sentry/memmap",
        "//pkg/sync",
        "//pkg/timing",
        "//pkg/usermem",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "platform_test",
    size = "small",
    srcs = ["mmap_min_addr_test.go"],
    library = ":platform",
    deps = ["//pkg/hostarch"],
)
