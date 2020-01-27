load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "filetest",
    testonly = 1,
    srcs = ["filetest.go"],
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
