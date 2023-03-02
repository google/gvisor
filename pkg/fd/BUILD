load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "fd",
    srcs = ["fd.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/atomicbitops",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "fd_test",
    size = "small",
    srcs = ["fd_test.go"],
    library = ":fd",
    deps = [
        "//pkg/atomicbitops",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
