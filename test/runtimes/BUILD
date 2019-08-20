# These packages are used to run language runtime tests inside gVisor sandboxes.

load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("//test:build_defs.bzl", "runtime_test")

package(licenses = ["notice"])

go_library(
    name = "runtimes",
    srcs = ["runtimes.go"],
    importpath = "gvisor.dev/gvisor/test/runtimes",
)

runtime_test(
    name = "runtimes_test",
    size = "small",
    srcs = ["runtimes_test.go"],
    embed = [":runtimes"],
    tags = [
        # Requires docker and runsc to be configured before the test runs.
        "manual",
        "local",
    ],
    deps = ["//test/testutil"],
)
