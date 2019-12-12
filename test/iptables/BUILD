load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "iptables",
    srcs = [
        "filter_input.go",
        "iptables.go",
        "iptables_util.go",
    ],
    importpath = "gvisor.dev/gvisor/test/iptables",
    visibility = ["//test/iptables:__subpackages__"],
)

go_test(
    name = "iptables_test",
    srcs = [
        "iptables_test.go",
    ],
    embed = [":iptables"],
    tags = [
        "local",
        "manual",
    ],
    deps = [
        "//pkg/log",
        "//runsc/dockerutil",
        "//runsc/testutil",
    ],
)
