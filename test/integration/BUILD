load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("//test:build_defs.bzl", "runtime_test")

package(licenses = ["notice"])

runtime_test(
    name = "integration_test",
    size = "large",
    srcs = [
        "exec_test.go",
        "integration_test.go",
        "regression_test.go",
    ],
    embed = [":integration"],
    tags = [
        # Requires docker and runsc to be configured before the test runs.
        "manual",
        "local",
    ],
    deps = [
        "//pkg/abi/linux",
        "//test/testutil",
    ],
)

go_library(
    name = "integration",
    srcs = ["integration.go"],
    importpath = "gvisor.dev/gvisor/test/integration",
)
