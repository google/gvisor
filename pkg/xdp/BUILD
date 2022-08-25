load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "xdp",
    srcs = [
        "fillqueue.go",
        "rxqueue.go",
        "umem.go",
        "xdp.go",
        "xdp_unsafe.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/log",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
