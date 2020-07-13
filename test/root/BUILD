load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/vm:defs.bzl", "vm_test")

package(licenses = ["notice"])

go_library(
    name = "root",
    srcs = ["root.go"],
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
        "runsc_test.go",
    ],
    data = [
        "//runsc",
    ],
    library = ":root",
    tags = [
        # Requires docker and runsc to be configured before the test runs.
        # Also, the test needs to be run as root. Note that below, the
        # root_vm_test relies on the default runtime 'runsc' being installed by
        # the default installer.
        "manual",
        "local",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/cleanup",
        "//pkg/test/criutil",
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
        "//runsc/cgroup",
        "//runsc/container",
        "//runsc/specutils",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@com_github_syndtr_gocapability//capability:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

vm_test(
    name = "root_vm_test",
    size = "large",
    shard_count = 1,
    targets = [":root_test"],
)
