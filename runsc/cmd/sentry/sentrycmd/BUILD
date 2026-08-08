load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "sentrycmd",
    srcs = [
        "boot.go",
        "chroot.go",
        "umount_unsafe.go",
    ],
    visibility = ["//runsc:__subpackages__"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/abi/tpu",
        "//pkg/coretag",
        "//pkg/cpuid",
        "//pkg/fd",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/metric",
        "//pkg/prometheus",
        "//pkg/rdma",
        "//pkg/ring0",
        "//pkg/sentry/devices/nvproxy/nvconf",
        "//pkg/sentry/hostmm",
        "//pkg/sentry/platform",
        "//pkg/sentry/syscalls/linux",
        "//pkg/tcpip/nftables",
        "//pkg/timing",
        "//runsc/boot",
        "//runsc/cmd/sandboxsetup",
        "//runsc/cmd/util",
        "//runsc/config",
        "//runsc/flag",
        "//runsc/profile",
        "//runsc/specutils",
        "//runsc/starttime",
        "@com_github_google_subcommands//:go_default_library",
        "@com_github_moby_sys_capability//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "sentrycmd_test",
    size = "small",
    srcs = ["chroot_test.go"],
    library = ":sentrycmd",
    deps = [
        "//runsc/config",
        "//runsc/specutils",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
