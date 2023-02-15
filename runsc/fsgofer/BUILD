load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "fsgofer",
    srcs = [
        "fsgofer_amd64_unsafe.go",
        "fsgofer_arm64_unsafe.go",
        "fsgofer_unsafe.go",
        "lisafs.go",
    ],
    visibility = ["//runsc:__subpackages__"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/cleanup",
        "//pkg/fd",
        "//pkg/lisafs",
        "//pkg/log",
        "//pkg/marshal/primitive",
        "//pkg/syserr",
        "//runsc/config",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "lisafs_test",
    size = "small",
    srcs = ["lisafs_test.go"],
    deps = [
        ":fsgofer",
        "//pkg/lisafs",
        "//pkg/lisafs/testsuite",
        "//pkg/log",
        "//runsc/config",
    ],
)
