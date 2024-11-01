load("//pkg/sync/locking:locking.bzl", "declare_mutex", "declare_rwmutex")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_mutex(
    name = "processor_mutex",
    out = "processor_mutex.go",
    package = "fdbased",
    prefix = "processor",
)

declare_rwmutex(
    name = "endpoint_mutex",
    out = "endpoint_mutex.go",
    package = "fdbased",
    prefix = "endpoint",
)

declare_rwmutex(
    name = "injectable_endpoint_mutex",
    out = "injectable_endpoint_mutex.go",
    package = "fdbased",
    prefix = "injectableEndpoint",
)

go_library(
    name = "fdbased",
    srcs = [
        "endpoint.go",
        "endpoint_mutex.go",
        "endpoint_unsafe.go",
        "injectable_endpoint_mutex.go",
        "mmap.go",
        "mmap_nonlinux.go",
        "mmap_unsafe.go",
        "packet_dispatchers.go",
        "processor_mutex.go",
        "processors.go",
        "save_restore.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/buffer",
        "//pkg/rand",
        "//pkg/rawfile",
        "//pkg/sleep",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/tcpip",
        "//pkg/tcpip/hash/jenkins",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/stopfd",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/stack/gro",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "fdbased_test",
    size = "small",
    srcs = ["endpoint_test.go"],
    library = ":fdbased",
    deps = [
        "//pkg/buffer",
        "//pkg/rand",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
