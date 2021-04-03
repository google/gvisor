load("//tools:defs.bzl", "go_library")
load("//test/benchmarks:defs.bzl", "benchmark_test")

package(licenses = ["notice"])

go_library(
    name = "network",
    testonly = 1,
    srcs = [
        "network.go",
    ],
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/harness",
        "//test/benchmarks/tools",
    ],
)

benchmark_test(
    name = "iperf_test",
    srcs = [
        "iperf_test.go",
    ],
    library = ":network",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
        "//test/benchmarks/harness",
        "//test/benchmarks/tools",
    ],
)

benchmark_test(
    name = "node_test",
    srcs = [
        "node_test.go",
    ],
    library = ":network",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/harness",
        "//test/benchmarks/tools",
    ],
)

benchmark_test(
    name = "ruby_test",
    srcs = [
        "ruby_test.go",
    ],
    library = ":network",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/harness",
        "//test/benchmarks/tools",
    ],
)

benchmark_test(
    name = "nginx_test",
    srcs = [
        "nginx_test.go",
    ],
    library = ":network",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/harness",
        "//test/benchmarks/tools",
    ],
)

benchmark_test(
    name = "httpd_test",
    srcs = [
        "httpd_test.go",
    ],
    library = ":network",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
        "//test/benchmarks/harness",
        "//test/benchmarks/tools",
    ],
)
