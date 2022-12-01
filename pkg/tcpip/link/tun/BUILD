load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

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

go_library(
    name = "tun",
    srcs = [
        "device.go",
        "protocol.go",
        "tun_endpoint_refs.go",
        "tun_unsafe.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/bufferv2",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/packetsocket",
        "//pkg/tcpip/stack",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
