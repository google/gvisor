load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "base",
    testonly = 1,
    srcs = [
        "base.go",
    ],
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/harness",
    ],
)

go_test(
    name = "startup_test",
    size = "enormous",
    srcs = ["startup_test.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/base",
        "//test/benchmarks/harness",
    ],
)

go_test(
    name = "size_test",
    size = "enormous",
    srcs = ["size_test.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/base",
        "//test/benchmarks/harness",
        "//test/benchmarks/tools",
    ],
)

go_test(
    name = "sysbench_test",
    size = "enormous",
    srcs = ["sysbench_test.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/harness",
        "//test/benchmarks/tools",
    ],
)
