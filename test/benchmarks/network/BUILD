load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "network",
    testonly = 1,
    srcs = ["network.go"],
    deps = ["//test/benchmarks/harness"],
)

go_test(
    name = "network_test",
    size = "large",
    srcs = [
        "httpd_test.go",
        "iperf_test.go",
        "node_test.go",
    ],
    library = ":network",
    tags = [
        # Requires docker and runsc to be configured before test runs.
        "manual",
        "local",
    ],
    deps = [
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
        "//test/benchmarks/harness",
    ],
)
