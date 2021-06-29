load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

licenses(["notice"])

go_template_instance(
    name = "dir_refs",
    out = "dir_refs.go",
    package = "sys",
    prefix = "dir",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "dir",
    },
)

go_library(
    name = "sys",
    srcs = [
        "dir_refs.go",
        "kcov.go",
        "sys.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/coverage",
        "//pkg/errors/linuxerr",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/refsvfs2",
        "//pkg/sentry/arch",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/usermem",
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
