load("//test/secbench:defs.bzl", "secbench_test")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "filter",
    srcs = ["filter.go"],
    visibility = [
        "//runsc/boot:__subpackages__",
    ],
    deps = [
        "//pkg/log",
        "//pkg/seccomp",
        "//runsc/boot/filter/config",
    ],
)

secbench_test(
    name = "filter_bench_test",
    srcs = ["filter_bench_test.go"],
    deps = [
        ":filter",
        "//pkg/abi/linux",
        "//pkg/seccomp",
        "//pkg/sentry/platform/kvm",
        "//pkg/sentry/platform/systrap",
        "//runsc/boot/filter/config",
        "//test/secbench",
        "//test/secbench/secbenchdef",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "filter_fuzz_test",
    srcs = [
        "filter_fuzz_golden_test.go",
        "filter_fuzz_test.go",
    ],
    data = ["filter_fuzz_golden.bpf"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bpf",
        "//pkg/seccomp",
        "//pkg/sentry/platform/systrap",
        "//pkg/test/testutil",
        "//runsc/boot/filter/config",
        "//test/secfuzz",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
