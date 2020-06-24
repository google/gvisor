load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "tests",
    srcs = [
        "array.go",
        "bench.go",
        "integer.go",
        "load.go",
        "map.go",
        "register.go",
        "struct.go",
        "tests.go",
    ],
    deps = [
        "//pkg/state",
        "//pkg/state/pretty",
    ],
)

go_test(
    name = "tests_test",
    size = "small",
    srcs = [
        "array_test.go",
        "bench_test.go",
        "bool_test.go",
        "float_test.go",
        "integer_test.go",
        "load_test.go",
        "map_test.go",
        "register_test.go",
        "string_test.go",
        "struct_test.go",
    ],
    library = ":tests",
    deps = [
        "//pkg/state",
        "//pkg/state/wire",
    ],
)
