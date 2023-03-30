load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

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
    pure = True,
    tags = [
        "local",
        "manual",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/cleanup",
        "//pkg/test/criutil",
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
        "//runsc/cgroup",
        "//runsc/config",
        "//runsc/container",
        "//runsc/flag",
        "//runsc/specutils",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@com_github_syndtr_gocapability//capability:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "portforward_test",
    srcs = ["portforward_test.go"],
    pure = True,
    tags = [
        "local",
        "manual",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/cleanup",
        "//pkg/test/dockerutil",
        "//runsc/config",
        "//runsc/flag",
        "//runsc/specutils",
        "@com_github_syndtr_gocapability//capability:go_default_library",
        "@org_golang_x_sync//errgroup:go_default_library",
    ],
)
