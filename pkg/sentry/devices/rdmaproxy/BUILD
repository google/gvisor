load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "rdmaproxy_test",
    size = "small",
    srcs = ["driver_test.go"],
    library = ":rdmaproxy",
    deps = [
        "//pkg/sentry/kernel",
    ],
)

go_library(
    name = "rdmaproxy",
    srcs = [
        "driver.go",
        "rdmaproxy.go",
        "rdmaproxy_ioctl.go",
        "rdmaproxy_ioctl_unsafe.go",
        "seccomp_filter.go",
    ],
    visibility = [
        "//pkg/sentry:internal",
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/cleanup",
        "//pkg/context",
        "//pkg/devutil",
        "//pkg/errors/linuxerr",
        "//pkg/fdnotifier",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/seccomp",
        "//pkg/sentry/arch",
        "//pkg/sentry/fsutil",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/mm",
        "//pkg/sentry/vfs",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
