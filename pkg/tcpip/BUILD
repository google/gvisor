package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_stateify", "go_test")

go_stateify(
    name = "tcpip_state",
    srcs = [
        "tcpip.go",
    ],
    out = "tcpip_state.go",
    package = "tcpip",
)

go_library(
    name = "tcpip",
    srcs = [
        "tcpip.go",
        "tcpip_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/state",
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
