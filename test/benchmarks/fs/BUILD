load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "fs",
    srcs = ["fs.go"],
)

go_test(
    name = "fs_test",
    size = "large",
    srcs = ["bazel_test.go"],
    library = ":fs",
    tags = [
        # Requires docker and runsc to be configured before test runs.
        "local",
        "manual",
    ],
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/harness",
    ],
)
