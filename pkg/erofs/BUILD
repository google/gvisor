load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "erofs",
    srcs = ["erofs.go"],
    marshal = True,
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/cleanup",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
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
