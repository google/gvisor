package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "seqfile",
    srcs = ["seqfile.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/seqfile",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/proc/device",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)

go_test(
    name = "seqfile_test",
    size = "small",
    srcs = ["seqfile_test.go"],
    embed = [":seqfile"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/ramfs",
        "//pkg/sentry/usermem",
    ],
)
