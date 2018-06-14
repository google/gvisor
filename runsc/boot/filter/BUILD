package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "filter",
    srcs = [
        "config.go",
        "config_go110.go",
        "config_go111.go",
        "extra_filters.go",
        "extra_filters_msan.go",
        "extra_filters_race.go",
        "filter.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/runsc/boot/filter",
    visibility = [
        "//runsc/boot:__subpackages__",
    ],
    deps = [
        "//pkg/log",
        "//pkg/seccomp",
        "//pkg/sentry/platform",
        "//pkg/sentry/platform/kvm",
        "//pkg/sentry/platform/ptrace",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
