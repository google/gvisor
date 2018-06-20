package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_test(
    name = "image_test",
    size = "small",
    srcs = ["image_test.go"],
    data = ["latin10k.txt"],
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
    importpath = "gvisor.googlesource.com/gvisor/runsc/test/image",
)
