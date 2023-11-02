load("//tools:defs.bzl", "go_library", "go_test")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "dev",
    srcs = [
        "dev.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fspath",
        "//pkg/sentry/fsimpl/tmpfs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
    ],
)

go_test(
    name = "dev_test",
    size = "small",
    srcs = ["dev_test.go"],
    library = ":dev",
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/fspath",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/fsimpl/tmpfs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
    ],
)
