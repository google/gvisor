load("//tools:defs.bzl", "go_library", "go_test")

licenses(["notice"])

go_library(
    name = "proc",
    srcs = [
        "filesystem.go",
        "subtasks.go",
        "task.go",
        "task_files.go",
        "tasks.go",
        "tasks_files.go",
        "tasks_net.go",
        "tasks_sys.go",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/limits",
        "//pkg/sentry/mm",
        "//pkg/sentry/safemem",
        "//pkg/sentry/socket",
        "//pkg/sentry/socket/unix",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/tcpip/header",
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
        "//pkg/fspath",
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fsimpl/testutil",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
    ],
)
