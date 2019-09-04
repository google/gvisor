load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "root",
    srcs = ["root.go"],
    importpath = "gvisor.dev/gvisor/test/root",
)

go_test(
    name = "root_test",
    size = "small",
    srcs = [
        "cgroup_test.go",
        "chroot_test.go",
        "crictl_test.go",
    ],
    embed = [":root"],
    tags = [
        # Requires docker and runsc to be configured before the test runs.
        # Also test only runs as root.
        "manual",
        "local",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//runsc/cgroup",
        "//runsc/criutil",
        "//runsc/dockerutil",
        "//runsc/specutils",
        "//runsc/testutil",
        "//test/root/testdata",
        "@com_github_syndtr_gocapability//capability:go_default_library",
    ],
)
