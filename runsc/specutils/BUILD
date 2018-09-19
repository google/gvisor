package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "specutils",
    srcs = [
        "cpu.go",
        "namespace.go",
        "specutils.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/runsc/specutils",
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/sentry/kernel/auth",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_opencontainers_runtime-spec//specs-go:go_default_library",
        "@com_github_syndtr_gocapability//capability:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "specutils_test",
    size = "small",
    srcs = ["specutils_test.go"],
    embed = [":specutils"],
    deps = ["@com_github_opencontainers_runtime-spec//specs-go:go_default_library"],
)
