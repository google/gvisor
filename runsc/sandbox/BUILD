load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "sandbox",
    srcs = [
        "memory.go",
        "network.go",
        "network_unsafe.go",
        "sandbox.go",
    ],
    embedsrcs = [
        "//runsc/sandbox/bpf:af_xdp_ebpf.o",  # keep
    ],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/cleanup",
        "//pkg/control/client",
        "//pkg/control/server",
        "//pkg/coverage",
        "//pkg/log",
        "//pkg/sentry/control",
        "//pkg/sentry/platform",
        "//pkg/sentry/seccheck",
        "//pkg/sync",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
        "//pkg/urpc",
        "//runsc/boot",
        "//runsc/boot/procfs",
        "//runsc/cgroup",
        "//runsc/config",
        "//runsc/console",
        "//runsc/donation",
        "//runsc/specutils",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_cilium_ebpf//:go_default_library",
        "@com_github_cilium_ebpf//link:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@com_github_syndtr_gocapability//capability:go_default_library",
        "@com_github_vishvananda_netlink//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "sandbox_test",
    size = "small",
    srcs = ["memory_test.go"],
    library = ":sandbox",
)
