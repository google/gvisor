load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "tpuproxy",
    srcs = [
        "devaddr_range.go",
        "devaddr_set.go",
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
        "//pkg/cleanup",
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
        "//pkg/sentry/fsimpl/kernfs",
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
    package = "tpuproxy",
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
    package = "tpuproxy",
    prefix = "DevAddr",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "DevAddrRange",
        "Value": "mm.PinnedRange",
        "Functions": "devAddrSetFuncs",
    },
)
