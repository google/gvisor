load("//pkg/sync/locking:locking.bzl", "declare_mutex", "declare_rwmutex")
load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

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

go_library(
    name = "cgroupfs",
    srcs = [
        "base.go",
        "cgroupfs.go",
        "cpu.go",
        "cpuacct.go",
        "cpuset.go",
        "devices.go",
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
