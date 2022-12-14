load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "portforward",
    srcs = [
        "portforward.go",
        "portforward_fd_rw.go",
    ],
    deps = [
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/vfs",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

go_test(
    name = "portforward_test",
    srcs = [
        "portforward_fd_rw_test.go",
    ],
    library = ":portforward",
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/vfs",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)
