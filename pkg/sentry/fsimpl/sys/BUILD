load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "sys",
    srcs = [
        "sys.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fsimpl/sys",
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
    ],
)

go_test(
    name = "sys_test",
    srcs = ["sys_test.go"],
    deps = [
        ":sys",
        "//pkg/abi/linux",
        "//pkg/sentry/fsimpl/testutil",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "@com_github_google_go-cmp//cmp:go_default_library",
    ],
)
