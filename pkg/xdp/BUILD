load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "xdp",
    srcs = [
        "completionqueue.go",
        "fillqueue.go",
        "rxqueue.go",
        "txqueue.go",
        "umem.go",
        "xdp.go",
        "xdp_unsafe.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/cleanup",
        "//pkg/log",
        "//pkg/memutil",
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
