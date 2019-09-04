load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "common",
    srcs = ["common.go"],
    importpath = "gvisor.dev/gvisor/test/runtimes/common",
    visibility = ["//:sandbox"],
)

go_test(
    name = "common_test",
    size = "small",
    srcs = ["common_test.go"],
    deps = [
        ":common",
        "//runsc/testutil",
    ],
)
