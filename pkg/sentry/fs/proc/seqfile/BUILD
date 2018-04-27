package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "seqfile_state",
    srcs = [
        "seqfile.go",
    ],
    out = "seqfile_state.go",
    package = "seqfile",
)

go_library(
    name = "seqfile",
    srcs = [
        "seqfile.go",
        "seqfile_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/seqfile",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/proc/device",
        "//pkg/sentry/fs/ramfs",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/usermem",
        "//pkg/state",
    ],
)

go_stateify(
    name = "seqfile_test_state",
    srcs = ["seqfile_test.go"],
    out = "seqfile_test_state.go",
    package = "seqfile",
)

go_test(
    name = "seqfile_test",
    size = "small",
    srcs = [
        "seqfile_test.go",
        "seqfile_test_state.go",
    ],
    embed = [":seqfile"],
    deps = [
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/ramfs/test",
        "//pkg/sentry/usermem",
    ],
)
