load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(licenses = ["notice"])  # Apache 2.0

go_library(
    name = "testutil",
    srcs = [
        "crictl.go",
        "docker.go",
        "testutil.go",
        "testutil_race.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/runsc/test/testutil",
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//runsc/boot",
        "//runsc/specutils",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_kr_pty//:go_default_library",
        "@com_github_opencontainers_runtime-spec//specs-go:go_default_library",
        "@com_github_syndtr_gocapability//capability:go_default_library",
    ],
)
