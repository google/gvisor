load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "config",
    srcs = [
        "config.go",
        "config_amd64.go",
        "config_arm64.go",
        "config_main.go",
        "config_precompiled.go",
        "config_profile.go",
        "extra_filters.go",
        "extra_filters_asan.go",
        "extra_filters_hostinet.go",
        "extra_filters_msan.go",
        "extra_filters_race.go",
        "extra_filters_race_amd64.go",
        "extra_filters_race_arm64.go",
    ],
    visibility = [
        "//runsc/boot/filter:__subpackages__",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/seccomp",
        "//pkg/seccomp/precompiledseccomp",
        "//pkg/sentry/devices/accel",
        "//pkg/sentry/devices/nvproxy",
        "//pkg/sentry/platform",
        "//pkg/sentry/platform/kvm",
        "//pkg/sentry/platform/systrap",
        "//pkg/sentry/socket/hostinet",
        "//pkg/tcpip/link/fdbased",
        "@org_golang_x_sync//errgroup:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "config_test",
    srcs = ["config_test.go"],
    library = ":config",
    deps = [
        "//pkg/seccomp",
        "//pkg/sentry/platform/kvm",
        "//pkg/sentry/platform/systrap",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
