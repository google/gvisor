package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "filetest",
    testonly = 1,
    srcs = ["filetest.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fs/filetest",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/anon",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/usermem",
        "//pkg/waiter",
    ],
)
