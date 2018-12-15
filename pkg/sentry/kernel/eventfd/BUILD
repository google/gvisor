package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "eventfd",
    srcs = ["eventfd.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/eventfd",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/fdnotifier",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/anon",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)

go_test(
    name = "eventfd_test",
    size = "small",
    srcs = ["eventfd_test.go"],
    embed = [":eventfd"],
    deps = [
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/usermem",
        "//pkg/waiter",
    ],
)
