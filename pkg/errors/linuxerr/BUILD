load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "linuxerr",
    srcs = [
        "internal.go",
        "linuxerr.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux/errno",
        "//pkg/errors",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "linuxerr_test",
    srcs = ["linuxerr_test.go"],
    deps = [
        ":linuxerr",
        "//pkg/errors",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
