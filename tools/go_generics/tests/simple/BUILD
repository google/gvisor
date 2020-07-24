load("//tools/go_generics/tests:defs.bzl", "go_generics_test")

go_generics_test(
    name = "simple",
    inputs = ["input.go"],
    output = "output.go",
    suffix = "New",
    types = {
        "T": "Q",
    },
)

# @unused
glaze_ignore = [
    "input.go",
    "output.go",
]
