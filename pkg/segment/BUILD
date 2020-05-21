load("//tools/go_generics:defs.bzl", "go_template")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

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
        # trackGaps must either be 0 or 1.
        "trackGaps",
    ],
    types = [
        "Key",
        "Range",
        "Value",
        "Functions",
    ],
)
