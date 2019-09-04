load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_test(
    name = "image_test",
    size = "large",
    srcs = [
        "image_test.go",
    ],
    data = [
        "latin10k.txt",
        "mysql.sql",
        "ruby.rb",
        "ruby.sh",
    ],
    embed = [":image"],
    tags = [
        # Requires docker and runsc to be configured before the test runs.
        "manual",
        "local",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//runsc/dockerutil",
        "//runsc/testutil",
    ],
)

go_library(
    name = "image",
    srcs = ["image.go"],
    importpath = "gvisor.dev/gvisor/test/image",
)
