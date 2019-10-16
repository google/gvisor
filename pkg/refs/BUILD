load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_template_instance(
    name = "weak_ref_list",
    out = "weak_ref_list.go",
    package = "refs",
    prefix = "weakRef",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*WeakRef",
        "Linker": "*WeakRef",
    },
)

go_library(
    name = "refs",
    srcs = [
        "refcounter.go",
        "refcounter_state.go",
        "weak_ref_list.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/refs",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
    ],
)

go_test(
    name = "refs_test",
    size = "small",
    srcs = ["refcounter_test.go"],
    embed = [":refs"],
)
