load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

licenses(["notice"])

go_template_instance(
    name = "dir_refs",
    out = "dir_refs.go",
    package = "cgroupfs",
    prefix = "dir",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "dir",
    },
)

go_library(
    name = "cgroupfs",
    srcs = [
        "base.go",
        "cgroupfs.go",
        "cpu.go",
        "cpuacct.go",
        "cpuset.go",
        "dir_refs.go",
        "memory.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/coverage",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/refsvfs2",
        "//pkg/sentry/arch",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/usage",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
    ],
)
