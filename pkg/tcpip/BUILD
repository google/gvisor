package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "tcpip",
    srcs = [
        "tcpip.go",
        "time_unsafe.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip/buffer",
        "//pkg/waiter",
    ],
)

go_test(
    name = "tcpip_test",
    size = "small",
    srcs = ["tcpip_test.go"],
    embed = [":tcpip"],
)
