load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "reviver",
    srcs = ["reviver.go"],
    importpath = "gvisor.dev/gvisor/tools/issue_reviver/reviver",
    visibility = [
        "//tools/issue_reviver:__subpackages__",
    ],
)

go_test(
    name = "reviver_test",
    size = "small",
    srcs = ["reviver_test.go"],
    embed = [":reviver"],
)
