load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "amdgpuproxy",
    srcs = [
        "amdgpuproxy.go",
        "drm.go",
        "ioctl_unsafe.go",
        "kfd.go",
        "seccomp_filters.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/amdgpu",
        "//pkg/abi/linux",
        "//pkg/amdgpu",
        "//pkg/context",
        "//pkg/devutil",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/marshal",
        "//pkg/seccomp",
        "//pkg/sentry/arch",
        "//pkg/sentry/fsutil",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/mm",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/usermem",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
