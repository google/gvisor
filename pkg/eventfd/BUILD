load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "eventfd",
    srcs = [
        "eventfd.go",
        "eventfd_unsafe.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/hostarch",
        "//pkg/tcpip/link/rawfile",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "eventfd_test",
    srcs = ["eventfd_test.go"],
    library = ":eventfd",
)
