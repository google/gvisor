load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(licenses = ["notice"])  # Apache 2.0

go_library(
    name = "root",
    srcs = ["root.go"],
    importpath = "gvisor.googlesource.com/gvisor/runsc/test/root",
)

go_test(
    name = "root_test",
    size = "small",
    srcs = [
        "cgroup_test.go",
        "chroot_test.go",
    ],
    embed = [":root"],
    tags = [
        # Requires docker and runsc to be configured before the test runs.
        # Also test only runs as root.
        "manual",
        "local",
    ],
    deps = [
        "//runsc/specutils",
        "//runsc/test/testutil",
        "@com_github_syndtr_gocapability//capability:go_default_library",
    ],
)
