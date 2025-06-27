load("//test/benchmarks:defs.bzl", "benchmark_test")
load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "database",
    testonly = 1,
    srcs = ["database.go"],
)

benchmark_test(
    name = "redis_test",
    srcs = ["redis_test.go"],
    library = ":database",
    use_for_pgo = True,
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/harness",
        "//test/benchmarks/tools",
        "//test/metricsviz",
    ],
)
