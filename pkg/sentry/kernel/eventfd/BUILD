load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "eventfd",
    srcs = ["eventfd.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/fdnotifier",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/anon",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/usermem",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)

go_test(
    name = "eventfd_test",
    size = "small",
    srcs = ["eventfd_test.go"],
    library = ":eventfd",
    deps = [
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/usermem",
        "//pkg/waiter",
    ],
)
