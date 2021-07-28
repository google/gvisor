load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "gomarshal",
    srcs = [
        "generator.go",
        "generator_interfaces.go",
        "generator_interfaces_array_newtype.go",
        "generator_interfaces_dynamic.go",
        "generator_interfaces_primitive_newtype.go",
        "generator_interfaces_struct.go",
        "generator_tests.go",
        "util.go",
    ],
    stateify = False,
    visibility = [
        "//:sandbox",
    ],
    deps = ["//tools/constraintutil"],
)
