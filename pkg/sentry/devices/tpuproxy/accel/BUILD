load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "accel",
    srcs = [
        "accel.go",
        "accel_fd.go",
        "accel_fd_mmap.go",
        "devaddr_range.go",
        "devaddr_set.go",
        "gasket_ioctl.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/gasket",
        "//pkg/abi/linux",
        "//pkg/abi/tpu",
        "//pkg/cleanup",
        "//pkg/context",
        "//pkg/devutil",
        "//pkg/errors/linuxerr",
        "//pkg/fdnotifier",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/safemem",
        "//pkg/seccomp",
        "//pkg/sentry/arch",
        "//pkg/sentry/devices/tpuproxy/util",
        "//pkg/sentry/fsimpl/eventfd",
        "//pkg/sentry/kernel",
        "//pkg/sentry/memmap",
        "//pkg/sentry/mm",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_exp//constraints:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_template_instance(
    name = "devaddr_range",
    out = "devaddr_range.go",
    package = "accel",
    prefix = "DevAddr",
    template = "//pkg/segment:generic_range",
    types = {
        "T": "uint64",
    },
)

go_template_instance(
    name = "devaddr_set",
    out = "devaddr_set.go",
    imports = {
        "mm": "gvisor.dev/gvisor/pkg/sentry/mm",
    },
    package = "accel",
    prefix = "DevAddr",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "DevAddrRange",
        "Value": "pinnedAccelMem",
        "Functions": "devAddrSetFuncs",
    },
)
