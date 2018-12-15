package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "fdpipe",
    srcs = [
        "pipe.go",
        "pipe_opener.go",
        "pipe_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/fdpipe",
    imports = ["gvisor.googlesource.com/gvisor/pkg/sentry/fs"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/fd",
        "//pkg/fdnotifier",
        "//pkg/log",
        "//pkg/secio",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/safemem",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)

go_test(
    name = "fdpipe_test",
    size = "small",
    srcs = [
        "pipe_opener_test.go",
        "pipe_test.go",
    ],
    embed = [":fdpipe"],
    deps = [
        "//pkg/fd",
        "//pkg/fdnotifier",
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fs",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
        "@com_github_google_uuid//:go_default_library",
    ],
)
