load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "platforms",
    srcs = ["platforms.go"],
    importpath = "gvisor.dev/gvisor/runsc/boot/platforms",
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/sentry/platform/kvm",
        "//pkg/sentry/platform/ptrace",
    ],
)
