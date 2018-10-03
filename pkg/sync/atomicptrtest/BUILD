package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

go_template_instance(
    name = "atomicptr_int",
    out = "atomicptr_int.go",
    package = "atomicptr",
    suffix = "Int",
    template = "//pkg/sync:generic_atomicptr",
    types = {
        "Value": "int",
    },
)

go_library(
    name = "atomicptr",
    srcs = ["atomicptr_int.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sync/atomicptr",
)

go_test(
    name = "atomicptr_test",
    size = "small",
    srcs = ["atomicptr_test.go"],
    embed = [":atomicptr"],
)
