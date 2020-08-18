load("//tools/go_generics/tests:defs.bzl", "go_generics_test")

go_generics_test(
    name = "consts",
    consts = {
        "c1": "20",
        "z": "600",
        "v": "3.3",
        "s": "\"def\"",
        "A": "20",
        "C": "100",
        "S": "\"def\"",
        "T": "\"ABC\"",
    },
    inputs = ["input.go"],
    output = "output.go",
)

# @unused
glaze_ignore = [
    "input.go",
    "output.go",
]
