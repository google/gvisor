load("//tools:defs.bzl", "go_library")
load("//test/benchmarks:defs.bzl", "benchmark_test")

package(licenses = ["notice"])

go_library(
    name = "network",
    testonly = 1,
    srcs = [
        "network.go",
        "static_server.go",
    ],
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/harness",
        "//test/benchmarks/tools",
    ],
)

benchmark_test(
    name = "network_test",
    size = "large",
    srcs = [
        "httpd_test.go",
        "iperf_test.go",
        "nginx_test.go",
        "node_test.go",
        "ruby_test.go",
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
