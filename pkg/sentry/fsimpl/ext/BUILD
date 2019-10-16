load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_stateify:defs.bzl", "go_library")
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
        "inode.go",
        "regular_file.go",
        "symlink.go",
        "utils.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fsimpl/ext",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/fd",
        "//pkg/log",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fsimpl/ext/disklayout",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/safemem",
        "//pkg/sentry/syscalls/linux",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
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
    embed = [":ext"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fsimpl/ext/disklayout",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//runsc/testutil",
        "@com_github_google_go-cmp//cmp:go_default_library",
        "@com_github_google_go-cmp//cmp/cmpopts:go_default_library",
    ],
)
