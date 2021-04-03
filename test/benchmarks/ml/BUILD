load("//tools:defs.bzl", "go_library")
load("//test/benchmarks:defs.bzl", "benchmark_test")

package(licenses = ["notice"])

go_library(
    name = "ml",
    testonly = 1,
    srcs = ["ml.go"],
)

benchmark_test(
    name = "tensorflow_test",
    srcs = ["tensorflow_test.go"],
    library = ":ml",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/harness",
        "//test/benchmarks/tools",
    ],
)
