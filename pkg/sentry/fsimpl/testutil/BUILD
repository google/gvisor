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
        "//pkg/cpuid",
        "//pkg/fspath",
        "//pkg/memutil",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/sched",
        "//pkg/sentry/limits",
        "//pkg/sentry/loader",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
        "//pkg/sentry/platform/kvm",
        "//pkg/sentry/platform/ptrace",
        "//pkg/sentry/time",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "@com_github_google_go-cmp//cmp:go_default_library",
    ],
)
