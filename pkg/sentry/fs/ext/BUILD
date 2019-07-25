package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "ext",
    srcs = [
        "dentry.go",
        "ext.go",
        "filesystem.go",
        "inode.go",
        "utils.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fs/ext",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/sentry/context",
        "//pkg/sentry/fs/ext/disklayout",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
    ],
)

go_test(
    name = "ext_test",
    size = "small",
    srcs = [
        "ext_test.go",
        "extent_test.go",
    ],
    data = [
        "//pkg/sentry/fs/ext:assets/bigfile.txt",
        "//pkg/sentry/fs/ext:assets/file.txt",
        "//pkg/sentry/fs/ext:assets/tiny.ext2",
        "//pkg/sentry/fs/ext:assets/tiny.ext3",
        "//pkg/sentry/fs/ext:assets/tiny.ext4",
    ],
    embed = [":ext"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fs/ext/disklayout",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//runsc/test/testutil",
        "@com_github_google_go-cmp//cmp:go_default_library",
        "@com_github_google_go-cmp//cmp/cmpopts:go_default_library",
    ],
)
