package(licenses = ["notice"])  # BSD

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "list_state",
    srcs = [
        "interface_list.go",
    ],
    out = "interface_list_state.go",
    package = "ilist",
)

go_library(
    name = "ilist",
    srcs = [
        "interface_list.go",
        "interface_list_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/ilist",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/state",
    ],
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
    opt_types = ["Linker"],
    visibility = ["//visibility:public"],
)
