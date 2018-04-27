package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "testutil",
    testonly = 1,
    srcs = [
        "testutil.go",
        "testutil_amd64.go",
        "testutil_amd64.s",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/platform/kvm/testutil",
    visibility = ["//pkg/sentry/platform/kvm:__pkg__"],
)
