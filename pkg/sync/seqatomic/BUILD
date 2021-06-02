load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template", "go_template_instance")

package(licenses = ["notice"])

go_template(
    name = "generic_seqatomic",
    srcs = ["generic_seqatomic_unsafe.go"],
    types = [
        "Value",
    ],
    visibility = ["//:sandbox"],
    deps = [
        ":sync",
        "//pkg/gohacks",
    ],
)

go_template_instance(
    name = "seqatomic_int",
    out = "seqatomic_int_unsafe.go",
    package = "seqatomic",
    suffix = "Int",
    template = ":generic_seqatomic",
    types = {
        "Value": "int",
    },
)

go_library(
    name = "seqatomic",
    srcs = ["seqatomic_int_unsafe.go"],
    deps = [
        "//pkg/gohacks",
        "//pkg/sync",
    ],
)

go_test(
    name = "seqatomic_test",
    size = "small",
    srcs = ["seqatomic_test.go"],
    library = ":seqatomic",
    deps = ["//pkg/sync"],
)
