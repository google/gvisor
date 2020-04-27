load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

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
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/sync",
    ],
)

go_test(
    name = "refs_test",
    size = "small",
    srcs = ["refcounter_test.go"],
    library = ":refs",
    deps = ["//pkg/sync"],
)
