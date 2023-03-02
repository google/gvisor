load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "runner",
    testonly = 1,
    srcs = ["main.go"],
    pure = True,
    visibility = ["//test/iptables:__subpackages__"],
    deps = ["//test/iptables"],
)
