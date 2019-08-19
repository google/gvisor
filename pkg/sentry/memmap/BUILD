load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools:defs.bzl", "go_library")

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

go_library(
    name = "memmap",
    srcs = [
        "mappable_range.go",
        "mapping_set.go",
        "mapping_set_impl.go",
        "memmap.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/memmap",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sentry/context",
        "//pkg/sentry/platform",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
    ],
)

go_test(
    name = "memmap_test",
    size = "small",
    srcs = ["mapping_set_test.go"],
    embed = [":memmap"],
    deps = ["//pkg/sentry/usermem"],
)
