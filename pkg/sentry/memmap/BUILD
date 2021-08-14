load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "mappable_range",
    out = "mappable_range.go",
    package = "memmap",
    prefix = "Mappable",
    template = "//pkg/segment:generic_range",
    types = {
        "T": "uint64",
    },
)

go_template_instance(
    name = "mapping_set_impl",
    out = "mapping_set_impl.go",
    package = "memmap",
    prefix = "Mapping",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "MappableRange",
        "Value": "MappingsOfRange",
        "Functions": "mappingSetFunctions",
    },
)

go_template_instance(
    name = "file_range",
    out = "file_range.go",
    package = "memmap",
    prefix = "File",
    template = "//pkg/segment:generic_range",
    types = {
        "T": "uint64",
    },
)

go_library(
    name = "memmap",
    srcs = [
        "file_range.go",
        "mappable_range.go",
        "mapping_set.go",
        "mapping_set_impl.go",
        "memmap.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/context",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/safemem",
        "//pkg/usermem",
    ],
)

go_test(
    name = "memmap_test",
    size = "small",
    srcs = ["mapping_set_test.go"],
    library = ":memmap",
    deps = ["//pkg/hostarch"],
)
