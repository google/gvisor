load("//tools:defs.bzl", "go_library", "go_test")

licenses(["notice"])

go_library(
    name = "sys",
    srcs = [
        "sys.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
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
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)
