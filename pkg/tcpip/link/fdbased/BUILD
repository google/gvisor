load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "fdbased",
    srcs = [
        "endpoint.go",
        "endpoint_unsafe.go",
        "mmap.go",
        "mmap_stub.go",
        "mmap_unsafe.go",
        "packet_dispatchers.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/bufferv2",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/rawfile",
        "//pkg/tcpip/link/stopfd",
        "//pkg/tcpip/stack",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "fdbased_test",
    size = "small",
    srcs = ["endpoint_test.go"],
    library = ":fdbased",
    deps = [
        "//pkg/bufferv2",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
