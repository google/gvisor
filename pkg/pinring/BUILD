load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "pinring",
    srcs = [
        "pinring.go",
        "pinring_unsafe.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "pinring_test",
    size = "medium",
    srcs = ["pinring_test.go"],
    library = ":pinring",
    deps = [
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
