load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "qdisc",
    srcs = ["packet_buffer_circular_list.go"],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/link/qdisc",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip/stack",
    ],
)
