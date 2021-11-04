load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "syserr",
    srcs = [
        "host_linux.go",
        "syserr.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux/errno",
        "//pkg/errors",
        "//pkg/errors/linuxerr",
        "//pkg/safecopy",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
