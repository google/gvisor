load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "seqatomic_int",
    out = "seqatomic_int_unsafe.go",
    package = "seqatomic",
    suffix = "Int",
    template = "//pkg/sync:generic_seqatomic",
    types = {
        "Value": "int",
    },
)

go_library(
    name = "seqatomic",
    srcs = ["seqatomic_int_unsafe.go"],
    importpath = "gvisor.dev/gvisor/pkg/sync/seqatomic",
    deps = [
        "//pkg/sync",
    ],
)

go_test(
    name = "seqatomic_test",
    size = "small",
    srcs = ["seqatomic_test.go"],
    embed = [":seqatomic"],
    deps = ["//pkg/sync"],
)
