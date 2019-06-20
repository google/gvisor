load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(
    default_visibility = ["//visibility:private"],
    licenses = ["notice"],
)

load("//tools/go_generics:defs.bzl", "go_template_instance")

go_template_instance(
    name = "int_range",
    out = "int_range.go",
    package = "segment",
    template = "//pkg/segment:generic_range",
    types = {
        "T": "int",
    },
)

go_template_instance(
    name = "int_set",
    out = "int_set.go",
    package = "segment",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "int",
        "Range": "Range",
        "Value": "int",
        "Functions": "setFunctions",
    },
)

go_library(
    name = "segment",
    testonly = 1,
    srcs = [
        "int_range.go",
        "int_set.go",
        "set_functions.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/segment/segment",
    deps = [
        "//pkg/state",
    ],
)

go_test(
    name = "segment_test",
    size = "small",
    srcs = ["segment_test.go"],
    embed = [":segment"],
)
