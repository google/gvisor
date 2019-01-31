load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "syserr",
    srcs = [
        "host_linux.go",
        "netstack.go",
        "syserr.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/syserr",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/syserror",
        "//pkg/tcpip",
    ],
)
