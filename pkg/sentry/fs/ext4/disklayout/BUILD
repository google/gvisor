package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "disklayout",
    srcs = [
        "block_group.go",
        "block_group_32.go",
        "block_group_64.go",
        "disklayout.go",
        "inode.go",
        "inode_new.go",
        "inode_old.go",
        "superblock.go",
        "superblock_32.go",
        "superblock_64.go",
        "superblock_old.go",
        "test_utils.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fs/ext4/disklayout",
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
    ],
)

go_test(
    name = "disklayout_test",
    size = "small",
    srcs = [
        "block_group_test.go",
        "inode_test.go",
        "superblock_test.go",
    ],
    embed = [":disklayout"],
    deps = ["//pkg/sentry/kernel/time"],
)
