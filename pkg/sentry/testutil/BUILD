load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "testutil",
    testonly = True,
    srcs = ["testutil.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/testutil",
    visibility = ["//third_party/golang/gvisor:__subpackages__"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/cpuid",
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
    ],
)
