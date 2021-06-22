load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "user",
    srcs = [
        "path.go",
        "user.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fspath",
        "//pkg/log",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/usermem",
    ],
)

go_test(
    name = "user_test",
    size = "small",
    srcs = ["user_test.go"],
    library = ":user",
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/tmpfs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/contexttest",
        "//pkg/usermem",
    ],
)
