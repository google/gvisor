load("//tools/go_generics/tests:defs.bzl", "go_generics_test")

go_generics_test(
    name = "imports",
    consts = {
        "n": "math.Uint32",
        "m": "math.Uint64",
    },
    imports = {
        "sync": "sync",
        "math": "mymathpath",
    },
    inputs = ["input.go"],
    output = "output.go",
    types = {
        "T": "sync.Mutex",
    },
)

# @unused
glaze_ignore = [
    "input.go",
    "output.go",
]
