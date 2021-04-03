load("//tools:defs.bzl", "go_library")
load("//test/benchmarks:defs.bzl", "benchmark_test")

package(licenses = ["notice"])

go_library(
    name = "database",
    testonly = 1,
    srcs = ["database.go"],
)

benchmark_test(
    name = "redis_test",
    srcs = ["redis_test.go"],
    library = ":database",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/harness",
        "//test/benchmarks/tools",
    ],
)
