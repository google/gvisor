load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "packet_list",
    out = "packet_list.go",
    package = "packet",
    prefix = "packet",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*packet",
        "Linker": "*packet",
    },
)

go_library(
    name = "packet",
    srcs = [
        "endpoint.go",
        "endpoint_state.go",
        "packet_list.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/bufferv2",
        "//pkg/log",
        "//pkg/sleep",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
        "//pkg/waiter",
    ],
)
