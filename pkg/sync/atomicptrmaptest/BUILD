load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(
    default_visibility = ["//visibility:private"],
    licenses = ["notice"],
)

go_template_instance(
    name = "test_atomicptrmap",
    out = "test_atomicptrmap_unsafe.go",
    package = "atomicptrmap",
    prefix = "test",
    template = "//pkg/sync:generic_atomicptrmap",
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
    template = "//pkg/sync:generic_atomicptrmap",
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
