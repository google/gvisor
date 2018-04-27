package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "eventfd_state",
    srcs = [
        "eventfd.go",
    ],
    out = "eventfd_state.go",
    package = "eventfd",
)

go_library(
    name = "eventfd",
    srcs = [
        "eventfd.go",
        "eventfd_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/eventfd",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/refs",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/anon",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/usermem",
        "//pkg/state",
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
