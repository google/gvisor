load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "sched",
    srcs = [
        "cpuset.go",
        "sched.go",
    ],
    visibility = ["//pkg/sentry:internal"],
)

go_test(
    name = "sched_test",
    size = "small",
    srcs = ["cpuset_test.go"],
    library = ":sched",
)
