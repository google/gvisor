package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "sched",
    srcs = [
        "cpuset.go",
        "sched.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/sched",
    visibility = ["//pkg/sentry:internal"],
)

go_test(
    name = "sched_test",
    size = "small",
    srcs = ["cpuset_test.go"],
    embed = [":sched"],
)
