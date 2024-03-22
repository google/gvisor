load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "tpuproxy",
    srcs = [
        "device.go",
        "ioctl_unsafe.go",
        "seccomp_filter.go",
        "tpu.go",
        "tpu_mmap.go",
        "vfio.go",
        "vfio_mmap.go",
    ],
    visibility = [
        "//pkg/sentry:internal",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/devutil",
        "//pkg/errors/linuxerr",
        "//pkg/fdnotifier",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/marshal/primitive",
        "//pkg/safemem",
        "//pkg/seccomp",
        "//pkg/sentry/arch",
        "//pkg/sentry/fsimpl/eventfd",
        "//pkg/sentry/kernel",
        "//pkg/sentry/memmap",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_exp//constraints:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
