load("//tools:defs.bzl", "go_library", "go_test")

licenses(["notice"])

go_library(
    name = "proc",
    srcs = [
        "filesystem.go",
        "subtasks.go",
        "task.go",
        "task_files.go",
        "task_net.go",
        "tasks.go",
        "tasks_files.go",
        "tasks_sys.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/log",
        "//pkg/safemem",
        "//pkg/sentry/fs",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/limits",
        "//pkg/sentry/mm",
        "//pkg/sentry/socket",
        "//pkg/sentry/socket/unix",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/usage",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/tcpip/header",
        "//pkg/usermem",
    ],
)

go_test(
    name = "proc_test",
    size = "small",
    srcs = [
        "tasks_sys_test.go",
        "tasks_test.go",
    ],
    library = ":proc",
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/fspath",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/fsimpl/testutil",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/usermem",
    ],
)
