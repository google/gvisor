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
    size = "enormous",
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
        "@com_github_docker_docker//go-units:go_default_library",
    ],
)

benchmark_test(
    name = "node_test",
    size = "enormous",
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
    size = "enormous",
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
    size = "enormous",
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
    size = "enormous",
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
