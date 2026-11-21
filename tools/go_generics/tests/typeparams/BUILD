load("//tools/go_generics/tests:defs.bzl", "go_generics_test")

package(default_applicable_licenses = ["//:license"])

go_generics_test(
    name = "typeparams",
    inputs = ["input.go"],
    output = "output.go",
    package = "tests",
    types = {
        "T": "MyT",
    },
)

# @unused
glaze_ignore = [
    "input.go",
    "output.go",
]
