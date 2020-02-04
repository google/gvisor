load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "gomarshal",
    srcs = [
        "generator.go",
        "generator_interfaces.go",
        "generator_tests.go",
        "util.go",
    ],
    stateify = False,
    visibility = [
        "//:sandbox",
    ],
    deps = ["//tools/tags"],
)
