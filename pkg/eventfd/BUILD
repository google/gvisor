load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "eventfd",
    srcs = [
        "eventfd.go",
        "eventfd_unsafe.go",
    ],
    visibility = [
        "//:sandbox",
        "//cloud/cluster/node/network/client/go:__pkg__",
    ],
    deps = [
        "//pkg/hostarch",
        "//pkg/rawfile",
        "//pkg/safecopy",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "eventfd_test",
    srcs = ["eventfd_test.go"],
    library = ":eventfd",
)
