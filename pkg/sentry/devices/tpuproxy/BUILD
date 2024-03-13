load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "tpuproxy",
    srcs = [
        "device.go",
        "seccomp_filter.go",
        "tpu.go",
        "tpu_mmap.go",
        "vfio.go",
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
        "//pkg/safemem",
        "//pkg/seccomp",
        "//pkg/sentry/arch",
        "//pkg/sentry/memmap",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
