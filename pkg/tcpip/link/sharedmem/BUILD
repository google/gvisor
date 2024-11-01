load("//pkg/sync/locking:locking.bzl", "declare_rwmutex")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_rwmutex(
    name = "endpoint_mutex",
    out = "endpoint_mutex.go",
    package = "sharedmem",
    prefix = "endpoint",
)

declare_rwmutex(
    name = "server_endpoint_mutex",
    out = "server_endpoint_mutex.go",
    package = "sharedmem",
    prefix = "serverEndpoint",
)

go_library(
    name = "sharedmem",
    srcs = [
        "endpoint_mutex.go",
        "queuepair.go",
        "rx.go",
        "server_endpoint_mutex.go",
        "server_rx.go",
        "server_tx.go",
        "sharedmem.go",
        "sharedmem_server.go",
        "sharedmem_unsafe.go",
        "tx.go",
    ],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/buffer",
        "//pkg/cleanup",
        "//pkg/eventfd",
        "//pkg/log",
        "//pkg/memutil",
        "//pkg/rawfile",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/sharedmem/pipe",
        "//pkg/tcpip/link/sharedmem/queue",
        "//pkg/tcpip/stack",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "sharedmem_test",
    srcs = ["sharedmem_test.go"],
    library = ":sharedmem",
    deps = [
        "//pkg/buffer",
        "//pkg/refs",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/sharedmem/pipe",
        "//pkg/tcpip/link/sharedmem/queue",
        "//pkg/tcpip/stack",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "sharedmem_server_test",
    size = "large",
    srcs = ["sharedmem_server_test.go"],
    deps = [
        ":sharedmem",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/adapters/gonet",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/qdisc/fifo",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/udp",
        "@org_golang_x_sync//errgroup:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
