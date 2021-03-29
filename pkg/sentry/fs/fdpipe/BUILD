load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "fdpipe",
    srcs = [
        "pipe.go",
        "pipe_opener.go",
        "pipe_state.go",
    ],
    imports = ["gvisor.dev/gvisor/pkg/sentry/fs"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/context",
        "//pkg/fd",
        "//pkg/fdnotifier",
        "//pkg/log",
        "//pkg/safemem",
        "//pkg/secio",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "fdpipe_test",
    size = "small",
    srcs = [
        "pipe_opener_test.go",
        "pipe_test.go",
    ],
    library = ":fdpipe",
    deps = [
        "//pkg/context",
        "//pkg/fd",
        "//pkg/fdnotifier",
        "//pkg/hostarch",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/fs",
        "//pkg/syserror",
        "//pkg/usermem",
        "@com_github_google_uuid//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
