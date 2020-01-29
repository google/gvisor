load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "atomicptr_int",
    out = "atomicptr_int_unsafe.go",
    package = "atomicptr",
    suffix = "Int",
    template = "//pkg/sync:generic_atomicptr",
    types = {
        "Value": "int",
    },
)

go_library(
    name = "atomicptr",
    srcs = ["atomicptr_int_unsafe.go"],
)

go_test(
    name = "atomicptr_test",
    size = "small",
    srcs = ["atomicptr_test.go"],
    library = ":atomicptr",
)
