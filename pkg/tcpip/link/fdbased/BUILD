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
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/rawfile",
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
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
