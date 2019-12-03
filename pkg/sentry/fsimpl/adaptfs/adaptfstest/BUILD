load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "adaptfstest",
    srcs = ["test_kernel.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fsimpl/adaptfs/adaptfstest",
    deps = [
        "//pkg/cpuid",
        "//pkg/memutil",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform/ptrace",
        "//pkg/sentry/time",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
    ],
)

go_test(
    name = "adaptfstest_test",
    size = "small",
    srcs = ["adaptfstest_test.go"],
    embed = [":adaptfstest"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/sentry/fs/proc",
        "//pkg/sentry/fsimpl/adaptfs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
    ],
)
