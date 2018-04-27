package(licenses = ["notice"])  # BSD

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "stack_state",
    srcs = [
        "registration.go",
        "stack.go",
    ],
    out = "stack_state.go",
    package = "stack",
)

go_library(
    name = "stack",
    srcs = [
        "linkaddrcache.go",
        "nic.go",
        "registration.go",
        "route.go",
        "stack.go",
        "stack_global_state.go",
        "stack_state.go",
        "transport_demuxer.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/stack",
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/ilist",
        "//pkg/sleep",
        "//pkg/state",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/ports",
        "//pkg/tcpip/seqnum",
        "//pkg/waiter",
    ],
)

go_test(
    name = "stack_x_test",
    size = "small",
    srcs = [
        "stack_test.go",
        "transport_test.go",
    ],
    deps = [
        ":stack",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/link/channel",
        "//pkg/waiter",
    ],
)

go_test(
    name = "stack_test",
    size = "small",
    srcs = ["linkaddrcache_test.go"],
    embed = [":stack"],
    deps = [
        "//pkg/sleep",
        "//pkg/tcpip",
    ],
)
