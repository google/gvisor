# These packages are used to run language runtime tests inside gVisor sandboxes.

load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library")
load("//runsc/test:build_defs.bzl", "runtime_test")

package(licenses = ["notice"])

go_library(
    name = "runtimes",
    srcs = ["runtimes.go"],
    importpath = "gvisor.dev/gvisor/runsc/test/runtimes",
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
    deps = ["//runsc/test/testutil"],
)

go_binary(
    name = "proctor-go",
    srcs = ["proctor-go.go"],
)

go_binary(
    name = "proctor-java",
    srcs = ["proctor-java.go"],
)

go_binary(
    name = "proctor-nodejs",
    srcs = ["proctor-nodejs.go"],
)

go_binary(
    name = "proctor-php",
    srcs = ["proctor-php.go"],
)

go_binary(
    name = "proctor-python",
    srcs = ["proctor-python.go"],
)
