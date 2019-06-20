load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "rawfile",
    srcs = [
        "blockingpoll_amd64.s",
        "blockingpoll_amd64_unsafe.go",
        "blockingpoll_unsafe.go",
        "errors.go",
        "rawfile_unsafe.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/link/rawfile",
    visibility = [
        "//visibility:public",
    ],
    deps = ["//pkg/tcpip"],
)
