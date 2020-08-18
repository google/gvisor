load("//tools/go_generics/tests:defs.bzl", "go_generics_test")

go_generics_test(
    name = "anon",
    anon = True,
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
