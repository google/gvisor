package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "ext",
    srcs = [
        "dentry.go",
        "ext.go",
        "inode.go",
        "utils.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fs/ext",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/sentry/fs/ext/disklayout",
        "//pkg/syserror",
    ],
)

go_test(
    name = "ext_test",
    size = "small",
    srcs = ["extent_test.go"],
    embed = [":ext"],
    deps = [
        "//pkg/binary",
        "//pkg/sentry/fs/ext/disklayout",
        "@com_github_google_go-cmp//cmp:go_default_library",
        "@com_github_google_go-cmp//cmp/cmpopts:go_default_library",
    ],
)
