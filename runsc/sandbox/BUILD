load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "sandbox",
    srcs = [
        "network.go",
        "network_unsafe.go",
        "sandbox.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/cleanup",
        "//pkg/control/client",
        "//pkg/control/server",
        "//pkg/coverage",
        "//pkg/log",
        "//pkg/sentry/control",
        "//pkg/sentry/platform",
        "//pkg/sync",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
        "//pkg/urpc",
        "//runsc/boot",
        "//runsc/boot/platforms",
        "//runsc/cgroup",
        "//runsc/config",
        "//runsc/console",
        "//runsc/specutils",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@com_github_syndtr_gocapability//capability:go_default_library",
        "@com_github_vishvananda_netlink//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
