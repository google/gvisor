load("//tools:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "sched",
    srcs = [
        "cpuset.go",
        "sched.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/kernel/sched",
    visibility = ["//pkg/sentry:internal"],
)

go_test(
    name = "sched_test",
    size = "small",
    srcs = ["cpuset_test.go"],
    embed = [":sched"],
)
