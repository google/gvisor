load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "buffer_list",
    out = "buffer_list.go",
    package = "buffer",
    prefix = "buffer",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*buffer",
        "Linker": "*buffer",
    },
)

go_library(
    name = "buffer",
    srcs = [
        "buffer.go",
        "buffer_list.go",
        "pool.go",
        "view.go",
        "view_unsafe.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/context",
        "//pkg/log",
    ],
)

go_test(
    name = "buffer_test",
    size = "small",
    srcs = [
        "buffer_test.go",
        "pool_test.go",
        "view_test.go",
    ],
    library = ":buffer",
    deps = [
        "//pkg/state",
    ],
)
