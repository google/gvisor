load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(licenses = ["notice"])  # Apache 2.0

go_library(
    name = "cgroup",
    srcs = ["cgroup.go"],
    importpath = "gvisor.googlesource.com/gvisor/runsc/cgroup",
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/log",
        "//runsc/specutils",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_opencontainers_runtime-spec//specs-go:go_default_library",
    ],
)

go_test(
    name = "cgroup_test",
    size = "small",
    srcs = ["cgroup_test.go"],
    embed = [":cgroup"],
)
