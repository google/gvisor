load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "container",
    testonly = True,
    srcs = ["container.go"],
    visibility = [
        "//test/iptables:__subpackages__",
        "//test/nftables:__subpackages__",
    ],
    deps = [
        "//pkg/log",
        "//pkg/test/dockerutil",
        "//test/netutils",
    ],
)
