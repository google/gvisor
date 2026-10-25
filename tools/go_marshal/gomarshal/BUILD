load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

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
    importpath = "gvisor.dev/gvisor/tools/go_marshal/gomarshal",
    stateify = False,
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//tools/constraintutil",
        "@org_golang_x_text//cases:go_default_library",
        "@org_golang_x_text//language:go_default_library",
    ],
)
