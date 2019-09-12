load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_generics:defs.bzl", "go_template", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "ilist",
    srcs = [
        "interface_list.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/ilist",
    visibility = ["//visibility:public"],
)

go_template_instance(
    name = "interface_list",
    out = "interface_list.go",
    package = "ilist",
    template = ":generic_list",
    types = {},
)

# This list is used for benchmarking.
go_template_instance(
    name = "test_list",
    out = "test_list.go",
    package = "ilist",
    prefix = "direct",
    template = ":generic_list",
    types = {
        "Element": "*direct",
        "Linker": "*direct",
    },
)

go_test(
    name = "list_test",
    size = "small",
    srcs = [
        "list_test.go",
        "test_list.go",
    ],
    embed = [":ilist"],
)

go_template(
    name = "generic_list",
    srcs = [
        "list.go",
    ],
    opt_types = [
        "Element",
        "ElementMapper",
        "Linker",
    ],
    visibility = ["//visibility:public"],
)
