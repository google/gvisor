load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "packetsocket",
    srcs = ["packetsocket.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/link/nested",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "packetsocket_x_test",
    size = "small",
    srcs = ["packetsocket_test.go"],
    deps = [
        ":packetsocket",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)
