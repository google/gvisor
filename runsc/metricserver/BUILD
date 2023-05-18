load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "metricserver",
    srcs = [
        "metricserver.go",
    ],
    visibility = ["//runsc:__subpackages__"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/log",
        "//pkg/prometheus",
        "//pkg/sentry/control",
        "//pkg/state",
        "//pkg/sync",
        "//runsc/config",
        "//runsc/container",
        "//runsc/sandbox",
    ],
)
