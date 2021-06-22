load("//tools:defs.bzl", "go_library", "go_test")

licenses(["notice"])

go_library(
    name = "verity",
    srcs = [
        "filesystem.go",
        "save_restore.go",
        "verity.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fspath",
        "//pkg/hostarch",
        "//pkg/marshal/primitive",
        "//pkg/merkletree",
        "//pkg/refsvfs2",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/fs/lock",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
    ],
)

go_test(
    name = "verity_test",
    srcs = [
        "verity_test.go",
    ],
    library = ":verity",
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fspath",
        "//pkg/sentry/arch",
        "//pkg/sentry/fsimpl/testutil",
        "//pkg/sentry/fsimpl/tmpfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/usermem",
    ],
)
