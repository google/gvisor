load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "dirent_list",
    out = "dirent_list.go",
    package = "ext",
    prefix = "dirent",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*dirent",
        "Linker": "*dirent",
    },
)

go_template_instance(
    name = "fstree",
    out = "fstree.go",
    package = "ext",
    prefix = "generic",
    template = "//pkg/sentry/vfs/genericfstree:generic_fstree",
    types = {
        "Dentry": "dentry",
    },
)

go_library(
    name = "ext",
    srcs = [
        "block_map_file.go",
        "dentry.go",
        "directory.go",
        "dirent_list.go",
        "ext.go",
        "extent_file.go",
        "file_description.go",
        "filesystem.go",
        "fstree.go",
        "inode.go",
        "regular_file.go",
        "symlink.go",
        "utils.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/fd",
        "//pkg/fspath",
        "//pkg/log",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/lock",
        "//pkg/sentry/fsimpl/ext/disklayout",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/syscalls/linux",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

go_test(
    name = "ext_test",
    size = "small",
    srcs = [
        "block_map_test.go",
        "ext_test.go",
        "extent_test.go",
    ],
    data = [
        "//pkg/sentry/fsimpl/ext:assets/bigfile.txt",
        "//pkg/sentry/fsimpl/ext:assets/file.txt",
        "//pkg/sentry/fsimpl/ext:assets/tiny.ext2",
        "//pkg/sentry/fsimpl/ext:assets/tiny.ext3",
        "//pkg/sentry/fsimpl/ext:assets/tiny.ext4",
    ],
    library = ":ext",
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/fspath",
        "//pkg/marshal/primitive",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/fsimpl/ext/disklayout",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/test/testutil",
        "//pkg/usermem",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_google_go_cmp//cmp/cmpopts:go_default_library",
    ],
)
