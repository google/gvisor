package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

load("//tools/go_generics:defs.bzl", "go_template")

go_template(
    name = "generic_range",
    srcs = ["range.go"],
    types = [
        "T",
    ],
)

go_template(
    name = "generic_set",
    srcs = [
        "set.go",
        "set_state.go",
    ],
    opt_consts = [
        "minDegree",
    ],
    types = [
        "Key",
        "Range",
        "Value",
        "Functions",
    ],
)
