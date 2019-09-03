package(licenses = ["notice"])

load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_template_instance(
    name = "linkaddrentry_list",
    out = "linkaddrentry_list.go",
    package = "stack",
    prefix = "linkAddrEntry",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*linkAddrEntry",
        "Linker": "*linkAddrEntry",
    },
)

go_library(
    name = "stack",
    srcs = [
        "icmp_rate_limit.go",
        "linkaddrcache.go",
        "linkaddrentry_list.go",
        "nic.go",
        "registration.go",
        "route.go",
        "stack.go",
        "stack_global_state.go",
        "transport_demuxer.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/stack",
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/ilist",
        "//pkg/sleep",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/hash/jenkins",
        "//pkg/tcpip/header",
        "//pkg/tcpip/iptables",
        "//pkg/tcpip/ports",
        "//pkg/tcpip/seqnum",
        "//pkg/waiter",
        "@org_golang_x_time//rate:go_default_library",
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
        "//pkg/tcpip/header",
        "//pkg/tcpip/iptables",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/loopback",
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

filegroup(
    name = "autogen",
    srcs = [
        "linkaddrentry_list.go",
    ],
    visibility = ["//:sandbox"],
)
