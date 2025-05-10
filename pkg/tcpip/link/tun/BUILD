load("//pkg/sync/locking:locking.bzl", "declare_mutex", "declare_rwmutex")
load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_template_instance(
    name = "tun_endpoint_refs",
    out = "tun_endpoint_refs.go",
    package = "tun",
    prefix = "tunEndpoint",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "tunEndpoint",
    },
)

declare_rwmutex(
    name = "device_mutex",
    out = "device_mutex.go",
    package = "tun",
    prefix = "device",
)

declare_mutex(
    name = "endpoint_mutex",
    out = "endpoint_mutex.go",
    package = "tun",
    prefix = "endpoint",
)

go_library(
    name = "tun",
    srcs = [
        "device.go",
        "device_mutex.go",
        "endpoint_mutex.go",
        "protocol.go",
        "tun_endpoint_refs.go",
        "tun_unsafe.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/buffer",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/nested",
        "//pkg/tcpip/link/packetsocket",
        "//pkg/tcpip/stack",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
