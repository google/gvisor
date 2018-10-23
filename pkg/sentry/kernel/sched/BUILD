load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])  # Apache 2.0

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
