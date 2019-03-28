load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "fdbased",
    srcs = [
        "endpoint.go",
        "endpoint_unsafe.go",
        "mmap.go",
        "mmap_amd64_unsafe.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/link/fdbased",
    visibility = [
        "//visibility:public",
    ],
    deps = [
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
    embed = [":fdbased"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/rawfile",
        "//pkg/tcpip/stack",
    ],
)
