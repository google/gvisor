load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "ml",
    testonly = 1,
    srcs = ["ml.go"],
    deps = ["//test/benchmarks/harness"],
)

go_test(
    name = "ml_test",
    size = "large",
    srcs = ["tensorflow_test.go"],
    library = ":ml",
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/harness",
    ],
)
