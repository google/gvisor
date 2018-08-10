package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library", "go_test")

go_binary(
    name = "uds_test_app",
    srcs = [
        "uds_test_app.go",
    ],
)

go_library(
    name = "container",
    srcs = [
        "container.go",
        "hook.go",
        "status.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/runsc/container",
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/log",
        "//pkg/sentry/control",
        "//pkg/syserror",
        "//runsc/boot",
        "//runsc/sandbox",
        "//runsc/specutils",
        "@com_github_opencontainers_runtime-spec//specs-go:go_default_library",
    ],
)

go_test(
    name = "container_test",
    size = "medium",
    srcs = ["container_test.go"],
    data = [
        ":uds_test_app",
        "//runsc",
    ],
    tags = [
        "requires-kvm",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/sentry/control",
        "//pkg/sentry/kernel/auth",
        "//pkg/unet",
        "//runsc/boot",
        "//runsc/container",
        "//runsc/specutils",
        "//runsc/test/testutil",
        "@com_github_opencontainers_runtime-spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
