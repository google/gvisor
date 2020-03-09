package(licenses = ["notice"])

load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

go_template_instance(
    name = "test_ctrie",
    out = "test_ctrie_unsafe.go",
    package = "ctrie",
    prefix = "test",
    template = "//pkg/ctrie:generic_ctrie",
    types = {
        "Key": "testKey",
        "Value": "testValue",
    },
)

go_template_instance(
    name = "test_alt_ctrie",
    out = "test_alt_ctrie_unsafe.go",
    package = "ctrie",
    prefix = "testAlt",
    template = "//pkg/ctrie:generic_ctrie",
    types = {
        "Key": "testAltKey",
        "Value": "testValue",
    },
)

go_library(
    name = "ctrie",
    srcs = [
        "test_alt_ctrie_unsafe.go",
        "test_ctrie_unsafe.go",
        "types.go",
    ],
)

go_test(
    name = "ctrie_test",
    size = "small",
    srcs = [
        "ctrie_test.go",
    ],
    library = ":ctrie",
)
