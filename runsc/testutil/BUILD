load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "testutil",
    testonly = 1,
    srcs = ["testutil.go"],
    importpath = "gvisor.dev/gvisor/runsc/testutil",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//runsc/boot",
        "//runsc/specutils",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_opencontainers_runtime-spec//specs-go:go_default_library",
    ],
)
