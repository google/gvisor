package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "disklayout",
    srcs = [
        "block_group.go",
        "block_group_32.go",
        "block_group_64.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fs/ext4/disklayout",
)

go_test(
    name = "disklayout_test",
    size = "small",
    srcs = ["block_group_test.go"],
    embed = [":disklayout"],
    deps = ["//pkg/binary"],
)
