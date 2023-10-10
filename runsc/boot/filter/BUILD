load("//test/secbench:defs.bzl", "secbench_test")
load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "filter",
    srcs = [
        "config.go",
        "config_amd64.go",
        "config_arm64.go",
        "config_profile.go",
        "extra_filters.go",
        "extra_filters_asan.go",
        "extra_filters_hostinet.go",
        "extra_filters_msan.go",
        "extra_filters_race.go",
        "extra_filters_race_amd64.go",
        "extra_filters_race_arm64.go",
        "filter.go",
    ],
    visibility = [
        "//runsc/boot:__subpackages__",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/seccomp",
        "//pkg/sentry/devices/accel",
        "//pkg/sentry/devices/nvproxy",
        "//pkg/sentry/platform",
        "//pkg/sentry/socket/hostinet",
        "//pkg/tcpip/link/fdbased",
        "@org_golang_x_sys//unix:go_default_library",
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
        "//test/secbench",
        "//test/secbench/secbenchdef",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
