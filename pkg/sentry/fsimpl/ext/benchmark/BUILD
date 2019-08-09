load("//tools/go_stateify:defs.bzl", "go_test")

package(licenses = ["notice"])

go_test(
    name = "benchmark_test",
    size = "small",
    srcs = ["benchmark_test.go"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fsimpl/ext",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
    ],
)
