load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "addr_range",
    out = "addr_range.go",
    package = "hostarch",
    prefix = "Addr",
    template = "//pkg/segment:generic_range",
    types = {
        "T": "Addr",
    },
)

go_test(
    name = "hostarch_test",
    size = "small",
    srcs = [
        "addr_range_seq_test.go",
        "addr_test.go",
    ],
    library = ":hostarch",
)

go_library(
    name = "hostarch",
    srcs = [
        "access_type.go",
        "addr.go",
        "addr_range.go",
        "addr_range_seq_unsafe.go",
        "hostarch.go",
        "hostarch_arm64.go",
        "hostarch_x86.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/gohacks",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
