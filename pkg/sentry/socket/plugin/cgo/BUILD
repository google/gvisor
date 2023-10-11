package(licenses = ["notice"])

load("//tools:defs.bzl", "go_library")

go_library(
    name = "cgo",
    srcs = [
        "socket_unsafe.go",
        "stack_unsafe.go",
        "util_unsafe.go",
    ],
    cgo = True,
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/abi/linux/errno",
        "//runsc/config",
    ],
    cdeps = [
        "@libtldk//:libtldk",
    ],
    copts = [
        "-march=native",
        "-I external/libtldk/lib/libtle_glue",
    ],
    clinkopts = [
        "-L external/libtldk",
    ],
)
