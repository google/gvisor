load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "ramfs",
    srcs = [
        "dir.go",
        "socket.go",
        "symlink.go",
        "tree.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/anon",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "ramfs_test",
    size = "small",
    srcs = ["tree_test.go"],
    library = ":ramfs",
    deps = [
        "//pkg/sentry/contexttest",
        "//pkg/sentry/fs",
    ],
)
