load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "disklayout",
    srcs = [
        "block_group.go",
        "block_group_32.go",
        "block_group_64.go",
        "dirent.go",
        "dirent_new.go",
        "dirent_old.go",
        "disklayout.go",
        "extent.go",
        "inode.go",
        "inode_new.go",
        "inode_old.go",
        "superblock.go",
        "superblock_32.go",
        "superblock_64.go",
        "superblock_old.go",
        "test_utils.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fsimpl/ext/disklayout",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
    ],
)

go_test(
    name = "disklayout_test",
    size = "small",
    srcs = [
        "block_group_test.go",
        "dirent_test.go",
        "extent_test.go",
        "inode_test.go",
        "superblock_test.go",
    ],
    embed = [":disklayout"],
    deps = ["//pkg/sentry/kernel/time"],
)
