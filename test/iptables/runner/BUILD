load("//tools:defs.bzl", "container_image", "go_binary", "go_image")

package(licenses = ["notice"])

go_binary(
    name = "runner",
    testonly = 1,
    srcs = ["main.go"],
    deps = ["//test/iptables"],
)

container_image(
    name = "iptables-base",
    base = "@iptables-test//image",
)

go_image(
    name = "runner-image",
    testonly = 1,
    srcs = ["main.go"],
    base = ":iptables-base",
    deps = ["//test/iptables"],
)
