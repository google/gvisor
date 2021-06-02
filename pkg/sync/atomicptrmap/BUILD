load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template", "go_template_instance")

package(
    default_visibility = ["//visibility:private"],
    licenses = ["notice"],
)

go_template(
    name = "generic_atomicptrmap",
    srcs = ["generic_atomicptrmap_unsafe.go"],
    opt_consts = [
        "ShardOrder",
    ],
    opt_types = [
        "Hasher",
    ],
    types = [
        "Key",
        "Value",
    ],
    deps = [
        "//pkg/gohacks",
        "//pkg/sync",
    ],
)

go_template_instance(
    name = "test_atomicptrmap",
    out = "test_atomicptrmap_unsafe.go",
    package = "atomicptrmap",
    prefix = "test",
    template = ":generic_atomicptrmap",
    types = {
        "Key": "int64",
        "Value": "testValue",
    },
)

go_template_instance(
    name = "test_atomicptrmap_sharded",
    out = "test_atomicptrmap_sharded_unsafe.go",
    consts = {
        "ShardOrder": "4",
    },
    package = "atomicptrmap",
    prefix = "test",
    suffix = "Sharded",
    template = ":generic_atomicptrmap",
    types = {
        "Key": "int64",
        "Value": "testValue",
    },
)

go_library(
    name = "atomicptrmap",
    testonly = 1,
    srcs = [
        "atomicptrmap.go",
        "test_atomicptrmap_sharded_unsafe.go",
        "test_atomicptrmap_unsafe.go",
    ],
    deps = [
        "//pkg/gohacks",
        "//pkg/sync",
    ],
)

go_test(
    name = "atomicptrmap_test",
    size = "small",
    srcs = ["atomicptrmap_test.go"],
    library = ":atomicptrmap",
    deps = ["//pkg/sync"],
)
