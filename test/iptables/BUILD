load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "iptables",
    testonly = 1,
    srcs = [
        "filter_input.go",
        "filter_output.go",
        "iptables.go",
        "iptables_util.go",
        "nat.go",
    ],
    visibility = ["//test/iptables:__subpackages__"],
    deps = [
        "//runsc/testutil",
    ],
)

go_test(
    name = "iptables_test",
    srcs = [
        "iptables_test.go",
    ],
    library = ":iptables",
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
