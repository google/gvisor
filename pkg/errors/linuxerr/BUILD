load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "linuxerr",
    srcs = ["linuxerr.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux/errno",
        "//pkg/errors",
    ],
)

go_test(
    name = "linuxerr_test",
    srcs = ["linuxerr_test.go"],
    deps = [
        ":linuxerr",
        "//pkg/abi/linux/errno",
        "//pkg/errors",
        "//pkg/syserror",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
