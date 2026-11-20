load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "syserr",
    srcs = [
        "host_darwin.go",
        "host_linux.go",
        "netstack.go",
        "syserr.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/syserr",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux/errno",
        "//pkg/errors",
        "//pkg/errors/linuxerr",
        "//pkg/safecopy",
        "//pkg/tcpip",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "syserr_test",
    size = "small",
    srcs = ["syserr_test.go"],
    embed = [":syserr"],
    deps = [
        "//pkg/errors",
        "//pkg/errors/linuxerr",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
