load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "erofs",
    srcs = [
        "erofs.go",
        "erofs_unsafe.go",
    ],
    marshal = True,
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/cleanup",
        "//pkg/errors/linuxerr",
        "//pkg/gohacks",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/marshal",
        "//pkg/safemem",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "erofs_test",
    size = "small",
    srcs = ["erofs_test.go"],
    library = ":erofs",
)
