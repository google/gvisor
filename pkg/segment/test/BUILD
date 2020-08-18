load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(
    default_visibility = ["//visibility:private"],
    licenses = ["notice"],
)

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

go_template_instance(
    name = "gap_set",
    out = "gap_set.go",
    consts = {
        "trackGaps": "1",
    },
    package = "segment",
    prefix = "gap",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "int",
        "Range": "Range",
        "Value": "int",
        "Functions": "gapSetFunctions",
    },
)

go_library(
    name = "segment",
    testonly = 1,
    srcs = [
        "gap_set.go",
        "int_range.go",
        "int_set.go",
        "set_functions.go",
    ],
    deps = [
        "//pkg/state",
    ],
)

go_test(
    name = "segment_test",
    size = "small",
    srcs = ["segment_test.go"],
    library = ":segment",
)
