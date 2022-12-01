load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//pkg/sync/locking:locking.bzl", "declare_mutex", "declare_rwmutex")

licenses(["notice"])

declare_mutex(
    name = "pids_controller_mutex",
    out = "pids_controller_mutex.go",
    package = "cgroupfs",
    prefix = "pidsController",
)

declare_rwmutex(
    name = "task_mutex",
    out = "task_mutex.go",
    package = "cgroupfs",
    prefix = "task",
)

go_template_instance(
    name = "dir_refs",
    out = "dir_refs.go",
    package = "cgroupfs",
    prefix = "dir",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "dir",
    },
)

go_library(
    name = "cgroupfs",
    srcs = [
        "base.go",
        "bitmap.go",
        "cgroupfs.go",
        "cpu.go",
        "cpuacct.go",
        "cpuset.go",
        "dir_refs.go",
        "job.go",
        "memory.go",
        "pids.go",
        "pids_controller_mutex.go",
        "task_mutex.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/bitmap",
        "//pkg/context",
        "//pkg/coverage",
        "//pkg/errors/linuxerr",
        "//pkg/fspath",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sentry/arch",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/usage",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/usermem",
    ],
)

go_test(
    name = "cgroupfs_test",
    size = "small",
    srcs = ["bitmap_test.go"],
    library = ":cgroupfs",
    deps = ["//pkg/bitmap"],
)
