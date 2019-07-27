load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "filter",
    srcs = [
        "config.go",
        "extra_filters.go",
        "extra_filters_msan.go",
        "extra_filters_race.go",
        "filter.go",
    ],
    importpath = "gvisor.dev/gvisor/runsc/boot/filter",
    visibility = [
        "//runsc/boot:__subpackages__",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/seccomp",
        "//pkg/sentry/platform",
        "//pkg/sentry/watchdog",
        "//pkg/tcpip/link/fdbased",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
