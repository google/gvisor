load("//pkg/sync/locking:locking.bzl", "declare_mutex", "declare_rwmutex")
load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "cgroup2fs",
    srcs = [
        "base_files.go",
        "cgroup.go",
        "controllers.go",
        "cpu.go",
        "cpuset.go",
        "event.go",
        "filesystem.go",
        "memory.go",
        "pids.go",
        "pids_mutex.go",
        "save_restore.go",
        "tasks_mutex.go",
        "tree_mutex.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/bitmap",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/usage",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

declare_rwmutex(
    name = "tree_mutex",
    out = "tree_mutex.go",
    package = "cgroup2fs",
    prefix = "tree",
)

declare_rwmutex(
    name = "tasks_mutex",
    out = "tasks_mutex.go",
    package = "cgroup2fs",
    prefix = "tasks",
)

declare_mutex(
    name = "pids_mutex",
    out = "pids_mutex.go",
    package = "cgroup2fs",
    prefix = "pids",
)
