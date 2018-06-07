package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "pagetables",
    srcs = [
        "allocator.go",
        "allocator_unsafe.go",
        "pagetables.go",
        "pagetables_amd64.go",
        "pagetables_x86.go",
        "pcids_x86.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/platform/ring0/pagetables",
    visibility = [
        "//pkg/sentry/platform/kvm:__subpackages__",
        "//pkg/sentry/platform/ring0:__subpackages__",
    ],
    deps = ["//pkg/sentry/usermem"],
)

go_test(
    name = "pagetables_test",
    size = "small",
    srcs = [
        "pagetables_amd64_test.go",
        "pagetables_test.go",
        "pcids_x86_test.go",
    ],
    embed = [":pagetables"],
    deps = ["//pkg/sentry/usermem"],
)
