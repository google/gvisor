load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "database",
    testonly = 1,
    srcs = ["database.go"],
    deps = ["//test/benchmarks/harness"],
)

go_test(
    name = "database_test",
    size = "enormous",
    srcs = [
        "redis_test.go",
    ],
    library = ":database",
    tags = [
        # Requires docker and runsc to be configured before test runs.
        "manual",
        "local",
    ],
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/harness",
    ],
)
