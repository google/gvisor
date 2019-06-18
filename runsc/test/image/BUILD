load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("//runsc/test:build_defs.bzl", "runtime_test")

package(licenses = ["notice"])

runtime_test(
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
    deps = ["//runsc/test/testutil"],
)

go_library(
    name = "image",
    srcs = ["image.go"],
    importpath = "gvisor.dev/gvisor/runsc/test/image",
)
