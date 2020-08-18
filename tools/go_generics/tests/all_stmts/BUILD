load("//tools/go_generics/tests:defs.bzl", "go_generics_test")

go_generics_test(
    name = "all_stmts",
    inputs = ["input.go"],
    output = "output.go",
    types = {
        "T": "Q",
    },
)

# @unused
glaze_ignore = [
    "input.go",
    "output.go",
]
