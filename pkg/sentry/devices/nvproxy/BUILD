load("//tools:defs.bzl", "go_library", "go_test")
load("//pkg/sync/locking:locking.bzl", "declare_mutex")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

declare_mutex(
    name = "objs_mutex",
    out = "objs_mutex.go",
    package = "nvproxy",
    prefix = "objs",
)

go_library(
    name = "nvproxy",
    srcs = [
        "frontend.go",
        "frontend_mmap.go",
        "frontend_unsafe.go",
        "nvproxy.go",
        "nvproxy_unsafe.go",
        "objs_mutex.go",
        "seccomp_filters.go",
        "uvm.go",
        "uvm_mmap.go",
        "uvm_unsafe.go",
        "version.go",
    ],
    visibility = [
        "//pkg/sentry:internal",
        "//tools/gpu:__subpackages__",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/abi/nvgpu",
        "//pkg/cleanup",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fdnotifier",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
        "//pkg/safemem",
        "//pkg/seccomp",
        "//pkg/sentry/arch",
        "//pkg/sentry/fsimpl/devtmpfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/memmap",
        "//pkg/sentry/mm",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "nvproxy_test",
    srcs = ["nvproxy_test.go"],
    library = ":nvproxy",
    deps = ["//pkg/abi/nvgpu"],
)
