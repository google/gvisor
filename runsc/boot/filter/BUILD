load("//pkg/seccomp/precompiledseccomp:defs.bzl", "precompiled_seccomp_rules")
load("//test/secbench:defs.bzl", "secbench_test")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

precompiled_seccomp_rules(
    name = "filter_precompiled",
    out = "filter_precompiled.go",
    exclude_in_fastbuild = True,
    out_package_name = "filter",
    programs_to_compile_go_import = "gvisor.dev/gvisor/runsc/boot/filter/config",
    programs_to_compile_go_library = "//runsc/boot/filter/config",
)

go_library(
    name = "filter",
    srcs = [
        "filter.go",
        "filter_precompiled.go",
    ],
    visibility = [
        "//runsc/boot:__subpackages__",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/seccomp",
        "//pkg/seccomp/precompiledseccomp",
        "//pkg/sync",
        "//runsc/boot/filter/config",
    ],
)

secbench_test(
    name = "filter_bench_test",
    srcs = ["filter_bench_test.go"],
    features = ["no_default_linker_script"],
    deps = [
        ":filter",
        "//pkg/abi/linux",
        "//pkg/seccomp",
        "//pkg/sentry/devices/nvproxy/nvconf",
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
        "filter_fuzz_test.go",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/seccomp",
        "//pkg/sentry/platform/systrap",
        "//runsc/boot/filter/config",
        "//test/secfuzz",
    ],
)
