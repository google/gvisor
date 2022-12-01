load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "testutil",
    testonly = 1,
    srcs = [
        "kernel.go",
        "testutil.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/cpuid",
        "//pkg/fspath",
        "//pkg/hostarch",
        "//pkg/memutil",
        "//pkg/sentry/fsimpl/tmpfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/sched",
        "//pkg/sentry/limits",
        "//pkg/sentry/loader",
        "//pkg/sentry/mm",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
        "//pkg/sentry/platform/kvm",
        "//pkg/sentry/platform/ptrace",
        "//pkg/sentry/time",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/usermem",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)
