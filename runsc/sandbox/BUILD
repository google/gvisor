package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "sandbox",
    srcs = [
        "console.go",
        "namespace.go",
        "network.go",
        "sandbox.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/runsc/sandbox",
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/control/client",
        "//pkg/control/server",
        "//pkg/log",
        "//pkg/sentry/control",
        "//pkg/urpc",
        "//runsc/boot",
        "//runsc/specutils",
        "@com_github_kr_pty//:go_default_library",
        "@com_github_opencontainers_runtime-spec//specs-go:go_default_library",
        "@com_github_vishvananda_netlink//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "sandbox_test",
    size = "small",
    srcs = ["sandbox_test.go"],
    data = [
        "//runsc",
    ],
    embed = [":sandbox"],
    deps = [
        "//pkg/log",
        "//runsc/test/testutil",
    ],
)
