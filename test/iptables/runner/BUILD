load("@io_bazel_rules_docker//go:image.bzl", "go_image")
load("@io_bazel_rules_docker//container:container.bzl", "container_image")

package(licenses = ["notice"])

container_image(
    name = "iptables-base",
    base = "@iptables-test//image",
)

go_image(
    name = "runner",
    testonly = 1,
    srcs = ["main.go"],
    base = ":iptables-base",
    deps = ["//test/iptables"],
)
