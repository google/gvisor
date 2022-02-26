load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "coretag",
    srcs = [
        "coretag.go",
        "coretag_unsafe.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "coretag_test",
    size = "small",
    srcs = [
        "coretag_test.go",
    ],
    library = ":coretag",
    deps = [
        "//pkg/hostos",
    ],
)
