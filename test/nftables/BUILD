load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "nftables",
    testonly = 1,
    srcs = [
        "filter_input.go",
        "filter_input_iptables.go",
        "iptables_util.go",
        "nftables.go",
        "nftables_util.go",
    ],
    visibility = ["//test/nftables:__subpackages__"],
    deps = ["//test/netutils"],
)

go_test(
    name = "nftables_test",
    size = "large",
    srcs = ["nftables_test.go"],
    data = ["//test/nftables/runner"],
    library = ":nftables",
    tags = [
        "local",
        "manual",
    ],
    deps = [
        "//pkg/log",
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
    ],
)
