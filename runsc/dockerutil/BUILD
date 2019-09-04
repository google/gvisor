load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "dockerutil",
    testonly = 1,
    srcs = ["dockerutil.go"],
    importpath = "gvisor.dev/gvisor/runsc/dockerutil",
    visibility = ["//:sandbox"],
    deps = [
        "//runsc/testutil",
        "@com_github_kr_pty//:go_default_library",
    ],
)
