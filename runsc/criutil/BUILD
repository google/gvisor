load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "criutil",
    testonly = 1,
    srcs = ["criutil.go"],
    importpath = "gvisor.dev/gvisor/runsc/criutil",
    visibility = ["//:sandbox"],
    deps = ["//runsc/testutil"],
)
