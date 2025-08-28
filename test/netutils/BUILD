load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "netutils",
    testonly = 1,
    srcs = ["utils.go"],
    visibility = [
        "//test/iptables:__subpackages__",
        "//test/nftables:__subpackages__",
    ],
    deps = ["//pkg/test/testutil"],
)
