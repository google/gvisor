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
        "main_test.go",
        "oom_score_adj_test.go",
    ],
    data = [
        "//runsc",
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
        "//runsc/boot",
        "//runsc/cgroup",
        "//runsc/container",
        "//runsc/criutil",
        "//runsc/dockerutil",
        "//runsc/specutils",
        "//runsc/testutil",
        "//test/root/testdata",
        "@com_github_opencontainers_runtime-spec//specs-go:go_default_library",
        "@com_github_syndtr_gocapability//capability:go_default_library",
    ],
)
