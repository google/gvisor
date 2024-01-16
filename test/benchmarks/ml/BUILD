load("//test/benchmarks:defs.bzl", "benchmark_test")
load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

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
