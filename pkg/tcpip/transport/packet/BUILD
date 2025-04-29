load("//pkg/sync/locking:locking.bzl", "declare_mutex", "declare_rwmutex")
load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_rwmutex(
    name = "endpoint_mutex",
    out = "endpoint_mutex.go",
    package = "packet",
    prefix = "endpoint",
)

declare_mutex(
    name = "endpoint_rcv_mutex",
    out = "endpoint_rcv_mutex.go",
    package = "packet",
    prefix = "rcv",
)

declare_rwmutex(
    name = "packet_mmap_mutex",
    out = "packet_mmap_mutex.go",
    package = "packet",
    prefix = "packetMmap",
)

declare_mutex(
    name = "last_error_mutex",
    out = "last_error_mutex.go",
    package = "packet",
    prefix = "lastError",
)

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
        "endpoint_mutex.go",
        "endpoint_rcv_mutex.go",
        "endpoint_state.go",
        "last_error_mutex.go",
        "packet_list.go",
        "packet_mmap_mutex.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/buffer",
        "//pkg/log",
        "//pkg/sleep",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
        "//pkg/waiter",
    ],
)

go_test(
    name = "packet_test",
    srcs = ["packet_test.go"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/ethernet",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/raw",
        "//pkg/waiter",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)
