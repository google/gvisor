load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "tun_endpoint_refs",
    out = "tun_endpoint_refs.go",
    package = "tun",
    prefix = "tunEndpoint",
    template = "//pkg/refsvfs2:refs_template",
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
        "//pkg/context",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/refsvfs2",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/stack",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
