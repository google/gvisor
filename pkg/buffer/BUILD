load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_template_instance(
    name = "buffer_list",
    out = "buffer_list.go",
    package = "buffer",
    prefix = "buffer",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*Buffer",
        "Linker": "*Buffer",
    },
)

go_library(
    name = "buffer",
    srcs = [
        "buffer.go",
        "buffer_list.go",
        "safemem.go",
        "view.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/buffer",
    visibility = ["//visibility:public"],
    deps = ["//pkg/sentry/safemem"],
)

go_test(
    name = "buffer_test",
    size = "small",
    srcs = ["view_test.go"],
    embed = [":buffer"],
)
