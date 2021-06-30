load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "seqfile",
    srcs = ["seqfile.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/proc/device",
        "//pkg/sentry/kernel/time",
        "//pkg/sync",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

go_test(
    name = "seqfile_test",
    size = "small",
    srcs = ["seqfile_test.go"],
    library = ":seqfile",
    deps = [
        "//pkg/context",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/ramfs",
        "//pkg/usermem",
    ],
)
